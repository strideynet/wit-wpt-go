package grpc

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/url"
	"time"

	wit_wpt_go "github.com/strideynet/wit-wpt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	witMetadataKey = "workload-identity-token"
	wptMetadataKey = "workload-proof-token"
)

// WITSource is a function used by the client-side RPCCredential to fetch the
// WIT to use for minting WPTs.
type WITSource func(ctx context.Context) (*wit_wpt_go.WIT, error)

type WPTRPCCredential struct {
	witSource WITSource
	audSource ClientAudSource
}

func NewWPTRPCCredential(
	source WITSource,
	audSource ClientAudSource,
) *WPTRPCCredential {
	return &WPTRPCCredential{
		witSource: source,
		audSource: audSource,
	}
}

func (c *WPTRPCCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// Note: weirdly the URI passed in here looks something like:
	// https://service.example.com/some.Service
	// and omits the method being invoked. So this is not actually the target
	// URI being used in the underlying HTTP/2 transport. Hence, we need to use
	// the hostport from the URI and then use the RequestInfo to determine the
	// actual service/method being invoked.
	wit, err := c.witSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting WIT: %w", err)
	}

	reqInfo, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing request info in context")
	}
	parsedURI, err := url.Parse(uri[0])
	if err != nil {
		return nil, fmt.Errorf("parsing URI %q: %w", parsedURI, err)
	}
	aud := c.audSource(parsedURI, reqInfo)

	wpt, err := wit_wpt_go.MintWPT(
		wit,
		wit_wpt_go.WithExpiry(time.Now().Add(1*time.Minute)),
		wit_wpt_go.WithAudience(aud),
	)
	if err != nil {
		return nil, fmt.Errorf("minting WPT: %w", err)
	}

	return map[string]string{
		witMetadataKey: wit.Signed,
		wptMetadataKey: wpt.Signed,
	}, nil

}

func (c *WPTRPCCredential) RequireTransportSecurity() bool {
	// Realistically, we'd want this to be true, but for testing purposes,
	// it's a little easier if we don't have to setup transport security for
	// now.
	return false
}

// ClientAudSource is a function used by the client-side RPCCredential to
// generate the correct audience for the WPT based on the request.
type ClientAudSource func(url *url.URL, reqInfo credentials.RequestInfo) string

var DefaultClientAudSource ClientAudSource = func(
	in *url.URL,
	reqInfo credentials.RequestInfo,
) string {
	// Produces: "service.example.com/some.Service/Method
	out := url.URL{
		Scheme: "https", // TODO: Actually determine this?
		Host:   in.Host,
		Path:   reqInfo.Method,
	}
	return out.String()
}

// ServerAudSource is a function used by the server-side interceptor to
// determine the expected audience for incoming WPTs.
//
// TODO: Ideally, we'd modify this so it checks an incoming aud. A "AudChecker"
// as opposed to an "AudSource". This would allow support for a model where the
// server expects one of a list of valid audiences which can be fairly common
// if the server has multiple identities or is exposed by multiple DNS names.
type ServerAudSource func(fullMethod string) string

var DefaultServerAudSource = func(
	hostPort string,
) ServerAudSource {
	return func(fullMethod string) string {
		out := url.URL{
			Scheme: "https", // TODO: Actually determine this?
			Host:   hostPort,
			Path:   fullMethod,
		}
		return out.String()
	}
}

type WITAuthInterceptor struct {
	// TODO: take this as a more "generic" trust bundle.
	issuer    ed25519.PublicKey
	audSource ServerAudSource
}

func NewWITAuthInterceptor(
	issuer ed25519.PublicKey,
	audSource ServerAudSource,
) *WITAuthInterceptor {
	return &WITAuthInterceptor{
		issuer:    issuer,
		audSource: audSource,
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

func (i *WITAuthInterceptor) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	id, err := i.extractAndValidate(ss.Context(), info.FullMethod)
	if err != nil {
		return fmt.Errorf("extracting and validating wit/wpt: %w", err)
	}

	ctx := contextWithIdentity(ss.Context(), id)
	wrapped := &wrappedServerStream{
		ServerStream: ss,
		ctx:          ctx,
	}

	return handler(wrapped, ss)
}

func (i *WITAuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	id, err := i.extractAndValidate(ctx, info.FullMethod)
	if err != nil {
		return nil, fmt.Errorf("extracting and validating wit/wpt: %w", err)
	}

	ctx = contextWithIdentity(ctx, id)
	return handler(ctx, req)
}

func (i *WITAuthInterceptor) extractAndValidate(
	ctx context.Context, fullMethod string,
) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.InvalidArgument, "missing metadata")
	}

	witToken := md[witMetadataKey]
	if len(witToken) != 1 {
		return "", status.Errorf(
			codes.Unauthenticated,
			"expected one workload-identity-token header, got %d",
			len(witToken),
		)
	}
	wptToken := md[wptMetadataKey]
	if len(wptToken) != 1 {
		return "", status.Errorf(
			codes.Unauthenticated,
			"expected one workload-proof-token header, got %d",
			len(wptToken),
		)
	}

	wit, wpt, err := wit_wpt_go.ValidateWPT(
		i.issuer,
		witToken[0],
		wptToken[0],
	)
	if err != nil {
		return "", status.Errorf(
			codes.Unauthenticated, "validating WIT/WPT: %v", err,
		)
	}
	// Validate audience is as expected.
	// TODO: It'd be nice if this was "core" functionality exposed by a
	// ValidateWPT func option? or similar? Mostly to avoid this being forgotten
	// and being a huge security footgun.
	wantAud := i.audSource(fullMethod)
	if wpt.Audience != wantAud {
		return "", status.Errorf(
			codes.Unauthenticated,
			"unexpected WPT audience %q, wanted %q",
			wpt.Audience,
			wantAud,
		)
	}

	return wit.ID.String(), nil
}

type identityContextKey struct{}

func contextWithIdentity(
	ctx context.Context, workloadIdentifier string,
) context.Context {
	// TODO: In an ideal world, we'd use a more structured type here so we can
	// indicate information such as the JTI of the WIT and WPT. But this does
	// fine for demonstrative purposes.
	return context.WithValue(ctx, identityContextKey{}, workloadIdentifier)
}

func IdentityFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(identityContextKey{}).(string)
	return id, ok
}
