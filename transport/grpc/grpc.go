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
	witMetadataKey = "Workload-Identity-Token"
	wptMetadataKey = "Workload-Proof-Token"
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
		return nil, fmt.Errorf("minting WPT: %w")
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

func (i *WITAuthInterceptor) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if err := i.extractAndValidate(ss.Context()); err != nil {
		return fmt.Errorf("extracting and validating wit/wpt: %w", err)
	}

	return handler(srv, ss)
}

func (i *WITAuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if err := i.extractAndValidate(ctx); err != nil {
		return nil, fmt.Errorf("extracting and validating wit/wpt: %w", err)
	}

	return handler(ctx, req)
}

func (i *WITAuthInterceptor) extractAndValidate(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument, "missing metadata")
	}

	witToken := md[witMetadataKey]
	if len(witToken) != 1 {
		return fmt.Errorf("expected one workload-identity-token header, got %d", len(witToken))
	}
	wptToken := md[wptMetadataKey]
	if len(wptToken) != 1 {
		return fmt.Errorf("expected one workload-proof-token header, got %d", len(wptToken))
	}
	return nil
}
