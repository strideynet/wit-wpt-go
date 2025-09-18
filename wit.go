package wit_wpt_go

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	witJWTType = "wimse-id+jwt"
)

// WIT
// TODO: This feels very overloaded, it represents three different possible "WIT"
// states:
//   - A WIT pre-signing
//   - A signed WIT with private key (e.g one you can use to create a WPT)
//   - A signed WIT without private key (e.g one used by a recipient to validate
//     a WPT) - usually you've unmarshaled this from the JWT representation.
type WIT struct {
	// ID is the SPIFFE ID of the WIT-SVID
	ID spiffeid.ID `json:"sub"`
	// PrivateKey is the private key for the WIT-SVID.
	// This will only be present for a "local" SVID (e.g. one that the workload
	// possesses)
	PrivateKey ed25519.PrivateKey `json:"-"`
	// TODO: probably need some custom stuff here to marshal this as expected.
	// TODO: Embed cnf a layer deeper :')
	PublicKey jose.JSONWebKey `json:"cnf"`
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string `json:"-"`
	// Expiry is the expiration time of the WIT-SVID as present in the `exp`
	// claim.
	Expiry time.Time `json:"exp"`
	// IssuedAt is the time that the WIT-SVID was issued as in the `iat` claim.
	IssuedAt time.Time `json:"iat"`
	// JTI is...
	JTI string `json:"jti"`

	// Signed is this WIT, but signed.
	Signed string `json:"-"`
}

// TODO: yoink this into a "fakeissuer" package.
func MintWIT(
	issuer ed25519.PrivateKey,
	exp time.Time,
	id spiffeid.ID,
) (*WIT, error) {
	witPubKey, witPrivKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating WIT keypair: %w", err)
	}

	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("generating WPT JTI: %w", err)
	}
	wit := &WIT{
		ID:         id,
		PrivateKey: witPrivKey,
		PublicKey: jose.JSONWebKey{
			Key:       witPubKey,
			Algorithm: string(jose.EdDSA),
		},
		Expiry:   exp,
		IssuedAt: time.Now(),
		JTI:      jti,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithType(witJWTType)
	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       issuer,
		Algorithm: jose.EdDSA,
	}, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("creating WIT signer: %w", err)
	}
	// TODO: handle times in a more jwtty way.
	signed, err := jwt.Signed(signer).Claims(wit).Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing WIT JWT: %w", err)
	}

	wit.Signed = signed
	return wit, nil
}
