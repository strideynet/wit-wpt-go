package grpc

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	wit_wpt_go "github.com/strideynet/wit-wpt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	witMetadataKey = "workload-identity-token"
	wptMetadataKey = "workload-proof-token"
)

type WITSource func(ctx context.Context) (*wit_wpt_go.WIT, error)

type WPTRPCCredential struct {
	witSource WITSource
	audience  string
}

func NewWPTRPCCredential(
	source WITSource,
	audience string,
) *WPTRPCCredential {
	return &WPTRPCCredential{
		witSource: source,
		audience:  audience,
	}
}

func (c *WPTRPCCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	wit, err := c.witSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting WIT: %w", err)
	}

	wpt, err := wit_wpt_go.MintWPT(
		wit,
		wit_wpt_go.WithExpiry(time.Now().Add(1*time.Minute)),
		wit_wpt_go.WithAudience(c.audience),
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

type WITAuthInterceptor struct {
	// TODO: take this as a more "generic" trust bundle.
	issuer       ed25519.PublicKey
	wantAudience string
}

func NewWITAuthInterceptor(
	issuer ed25519.PublicKey,
	wantAudience string,
) *WITAuthInterceptor {
	return &WITAuthInterceptor{
		issuer:       issuer,
		wantAudience: wantAudience,
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
	id, err := i.extractAndValidate(ss.Context())
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
	id, err := i.extractAndValidate(ctx)
	if err != nil {
		return nil, fmt.Errorf("extracting and validating wit/wpt: %w", err)
	}

	ctx = contextWithIdentity(ctx, id)
	return handler(ctx, req)
}

func (i *WITAuthInterceptor) extractAndValidate(ctx context.Context) (string, error) {
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
	if wpt.Audience != i.wantAudience {
		return "", status.Errorf(
			codes.Unauthenticated,
			"unexpected WPT audience %q, wanted %q",
			wpt.Audience,
			i.wantAudience,
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
