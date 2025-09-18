package wit_wpt_go

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	witJWTType = "wimse-id+jwt"
	wptJWTType = "wimse-proof+jwt"
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
	// TODO: JTI
	wit := &WIT{
		ID:         id,
		PrivateKey: witPrivKey,
		PublicKey: jose.JSONWebKey{
			Key:       witPubKey,
			Algorithm: string(jose.EdDSA),
		},
		Expiry:   exp,
		IssuedAt: time.Now(),
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

type WPT struct {
	Audience string    `json:"aud"`
	JTI      string    `json:"jti"`
	Expiry   time.Time `json:"exp"`

	WTH    string `json:"wth"`
	Signed string `json:"-"`
}

// TODO: ATH etc as func opts
func MintWPT(
	wit *WIT,
	audience string,
	expiresAt time.Time,
) (*WPT, error) {
	if wit.PrivateKey == nil {
		// This WIT is not "local" and cannot be used for signing.
		return nil, fmt.Errorf("WIT must have private key to be able to mint WPT")
	}
	if wit.Signed == "" {
		return nil, fmt.Errorf("WIT must be signed to be able to mint WPT")
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithType(wptJWTType)
	signer, err := jose.NewSigner(jose.SigningKey{
		Key:       wit.PrivateKey,
		Algorithm: jose.EdDSA,
	}, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("creating WPT signer: %w", err)
	}

	// TODO: JTI
	wth := base64UrlEncTokenHash(wit.Signed)
	wpt := &WPT{
		Audience: audience,
		WTH:      wth,
		Expiry:   expiresAt,
	}
	signed, err := jwt.Signed(signer).Claims(wpt).Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing WPT JWT: %w", err)
	}
	wpt.Signed = signed

	return wpt, nil
}

func base64UrlEncTokenHash(raw string) string {
	if raw == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(raw))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}

// ValidateWPT validates the WPT and WIT
// TODO: We'll need to either have functions that build on this that check
// things like the `aud` are as we expect, or, we can bundle that into this as
// functional opts.
func ValidateWPT(
	issuer ed25519.PublicKey,
	rawWIT string,
	rawWPT string,
) (*WIT, *WPT, error) {
	// First, we need to validate the WIT is signed by the issuer, and also
	// validate that none of the claims within the WIT have been violated
	// (e.g it has expired)...
	parsedWIT, err := jwt.ParseSigned(rawWIT, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, nil, fmt.Errorf("parsing WIT JWT: %w", err)
	}
	wit := &WIT{}
	if err := parsedWIT.Claims(issuer, wit); err != nil {
		return nil, nil, fmt.Errorf("validating WIT JWT: %w", err)
	}
	if len(parsedWIT.Headers) != 1 {
		return nil, nil, fmt.Errorf("WIT JWT must contain exactly one header")
	}
	if typ := parsedWIT.Headers[0]; typ.ExtraHeaders[jose.HeaderType] != witJWTType {
		return nil, nil, fmt.Errorf("invalid WIT JWT: expected type %v, got %v", witJWTType, typ)
	}

	// Now we can check the WPT is signed by the public key within the WIT.
	parsedWPT, err := jwt.ParseSigned(rawWPT, []jose.SignatureAlgorithm{
		// TODO: base this on the alg expressed within the WIT
		jose.EdDSA,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("parsing WPT JWT: %w", err)
	}
	wpt := &WPT{}
	if err := parsedWPT.Claims(wit.PublicKey, wpt); err != nil {
		return nil, nil, fmt.Errorf("validating WPT JWT: %w", err)
	}
	if len(parsedWPT.Headers) != 1 {
		return nil, nil, fmt.Errorf("WPT JWT must contain exactly one header")
	}
	if typ := parsedWPT.Headers[0]; typ.ExtraHeaders[jose.HeaderType] != wptJWTType {
		return nil, nil, fmt.Errorf("invalid WPT JWT: expected type %v, got %v", wptJWTType, typ)
	}
	// TODO: Check WTH

	return wit, wpt, nil
}
