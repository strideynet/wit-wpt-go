package grpc

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	wit_wpt_go "github.com/strideynet/wit-wpt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "google.golang.org/grpc/examples/features/proto/echo"
)

type server struct {
	// Largely cribbed from
	// https://github.com/grpc/grpc-go/blob/master/examples/features/interceptor/server/main.go
	pb.UnimplementedEchoServer
}

func (s *server) UnaryEcho(
	ctx context.Context, _ *pb.EchoRequest,
) (*pb.EchoResponse, error) {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		// This should technically never happen as the interceptor should
		// drop the request if unauthenticated.
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	message := fmt.Sprintf("Hello: %s", identity)

	return &pb.EchoResponse{Message: message}, nil
}

func (s *server) BidirectionalStreamingEcho(
	stream pb.Echo_BidirectionalStreamingEchoServer,
) error {
	identity, ok := IdentityFromContext(stream.Context())
	if !ok {
		// This should technically never happen as the interceptor should
		// drop the request if unauthenticated.
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}

	for {
		_, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		message := fmt.Sprintf("Hello: %s", identity)
		if err := stream.Send(&pb.EchoResponse{Message: message}); err != nil {
			return err
		}
	}
}

func serverSetup(
	t *testing.T, issuerPub ed25519.PublicKey,
) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := lis.Close()
		// We expect in normal circumstances that this listener will have been
		// closed through grpc.Server.Stop() already.
		if !errors.Is(err, net.ErrClosed) {
			require.NoError(t, err)
		}
	})

	witAuthInterceptor := NewWITAuthInterceptor(
		issuerPub,
		DefaultServerAudSource(lis.Addr().String()),
	)

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			witAuthInterceptor.UnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			witAuthInterceptor.StreamInterceptor,
		),
	)
	pb.RegisterEchoServer(srv, &server{})

	wg := &sync.WaitGroup{}
	wg.Go(func() {
		require.NoError(t, srv.Serve(lis))
	})
	t.Cleanup(func() {
		srv.Stop()
		wg.Wait()
	})

	return srv, lis
}

// TODO: It would be nice to extend this to show validation of server identity
// via a workload identity certificate (x509).
func TestGRPC(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(cryptorand.Reader)
	require.NoError(t, err)

	_, lis := serverSetup(t, issuerPub)

	clientWIT, err := wit_wpt_go.MintWIT(
		issuerPriv,
		time.Now().Add(time.Hour),
		spiffeid.RequireFromString("spiffe://example.com/test-client"),
	)
	require.NoError(t, err)
	clientCred := NewWPTRPCCredential(
		StaticWITSource(clientWIT),
		DefaultClientAudSource(),
	)
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithPerRPCCredentials(clientCred),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	echoClient := pb.NewEchoClient(conn)
	resp, err := echoClient.UnaryEcho(
		t.Context(), &pb.EchoRequest{Message: "Hello"},
	)
	require.NoError(t, err)
	require.Equal(t, "Hello: spiffe://example.com/test-client", resp.Message)
}
