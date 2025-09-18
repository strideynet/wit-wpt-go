package grpc

import (
	"context"
	"fmt"
	"time"

	wit_wpt_go "github.com/strideynet/wit-wpt-go"
)

type WPTRPCCredential struct {
	WITSource func(ctx context.Context) (*wit_wpt_go.WIT, error)
}

func (c *WPTRPCCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	wit, err := c.WITSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting WIT: %w", err)
	}

	wpt, err := wit_wpt_go.MintWPT(
		wit,
		wit_wpt_go.WithExpiry(time.Now().Add(1*time.Minute)),
		// TODO: Does user need to always explicitly set audience, or, can we
		// use the URI here?
		wit_wpt_go.WithAudience("https://example.com"),
	)
	if err != nil {
		return nil, fmt.Errorf("minting WPT: %w")
	}

	return map[string]string{
		"Workload-Identity-Token": wit.Signed,
		"Workload-Proof-Token":    wpt.Signed,
	}, nil

}

func (c *WPTRPCCredential) RequireTransportSecurity() bool {
	return true
}
