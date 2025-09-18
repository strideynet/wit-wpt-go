package wit_wpt_go

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestMintWIT(t *testing.T) {
	_, issuer, err := ed25519.GenerateKey(cryptorand.Reader)
	require.NoError(t, err)

	workloadIdentitier, err := spiffeid.FromString(
		"spiffe://example.com/my-workload",
	)
	require.NoError(t, err)

	wit, err := MintWIT(
		issuer,
		time.Now().Add(time.Hour),
		workloadIdentitier,
	)
	require.NoError(t, err)
	require.NotEmpty(t, wit.Signed)
}
