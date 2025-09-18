package grpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	wit_wpt_go "github.com/strideynet/wit-wpt-go"
	"google.golang.org/grpc"
)

func TestGRPC(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, lis.Close())
	})

	srv := grpc.NewServer()
	t.Cleanup(func() {
		srv.Stop()
	})
	wg := &sync.WaitGroup{}
	wg.Go(func() {
		require.NoError(t, srv.Serve(lis))
	})
	t.Cleanup(func() {
		wg.Wait()
	})

	clientCred := &WPTRPCCredential{
		WITSource: func(ctx context.Context) (*wit_wpt_go.WIT, error) {
			// TODO: Return a WIT
			return nil, fmt.Errorf("unimplemented")
		},
	}
	conn, err := grpc.NewClient(
		"TODO",
		grpc.WithPerRPCCredentials(clientCred),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})
}
