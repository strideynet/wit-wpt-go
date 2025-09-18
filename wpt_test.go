package wit_wpt_go

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestMintWPT(t *testing.T) {
	issuerPub, issuer, err := ed25519.GenerateKey(cryptorand.Reader)
	require.NoError(t, err)

	workloadIdentifier, err := spiffeid.FromString(
		"spiffe://example.com/my-workload",
	)
	require.NoError(t, err)

	wit, err := MintWIT(
		issuer,
		time.Now().Add(time.Hour),
		workloadIdentifier,
	)
	require.NoError(t, err)

	wpt, err := MintWPT(
		wit,
		WithAudience("https://app.example.com"),
		WithExpiry(time.Now().Add(time.Minute)),
		WithAccessToken("foobaraccesstoken"),
		WithTransactionToken("foobartxtoken"),
		WithOtherToken("foobarothertoken"),
	)
	require.NoError(t, err)
	require.NotEmpty(t, wpt.Signed)

	gotWIT, gotWPT, err := ValidateWPT(issuerPub, wit.Signed, wpt.Signed)
	require.NoError(t, err)
	require.NotEmpty(t, gotWIT)
	require.NotEmpty(t, gotWPT)
}
