package wit_wpt_go

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	wptJWTType = "wimse-proof+jwt"
)

type WPT struct {
	Audience string    `json:"aud"`
	JTI      string    `json:"jti"`
	Expiry   time.Time `json:"exp"`

	ATH    string `json:"ath,omitempty"`
	TTH    string `json:"tth,omitempty"`
	OTH    string `json:"oth,omitempty"`
	WTH    string `json:"wth"`
	Signed string `json:"-"`
}

type wptOptions struct {
	ath       string
	tth       string
	oth       string
	audience  string
	expiresAt time.Time
}

type WPTOption func(*wptOptions)

func WithAccessToken(tok string) WPTOption {
	return func(o *wptOptions) {
		o.ath = base64SHA256(tok)
	}
}

func WithAudience(audience string) WPTOption {
	return func(o *wptOptions) {
		o.audience = audience
	}
}

func WithExpiry(expiresAt time.Time) WPTOption {
	return func(o *wptOptions) {
		o.expiresAt = expiresAt
	}
}

func WithTransactionToken(tok string) WPTOption {
	return func(o *wptOptions) {
		o.tth = base64SHA256(tok)
	}
}

func WithOtherToken(tok string) WPTOption {
	return func(o *wptOptions) {
		o.oth = base64SHA256(tok)
	}
}

func MintWPT(
	wit *WIT,
	optFuncs ...WPTOption,
) (*WPT, error) {
	opts := &wptOptions{}
	for _, opt := range optFuncs {
		opt(opts)
	}

	switch {
	case wit.PrivateKey == nil:
		return nil, fmt.Errorf("WIT must have private key to be able to mint WPT")
	case wit.Signed == "":
		return nil, fmt.Errorf("WIT must have signed JWT to be able to mint WPT")
	case opts.audience == "":
		return nil, fmt.Errorf("audience is mandatory")
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

	wth := base64SHA256(wit.Signed)
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("generating WPT JTI: %w", err)
	}
	wpt := &WPT{
		Audience: opts.audience,
		WTH:      wth,
		Expiry:   opts.expiresAt,
		ATH:      opts.ath,
		JTI:      jti,
		TTH:      opts.tth,
		OTH:      opts.oth,
	}
	signed, err := jwt.Signed(signer).Claims(wpt).Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing WPT JWT: %w", err)
	}
	wpt.Signed = signed

	return wpt, nil
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
	if err := parsedWPT.Claims(wit.PublicKey.JWK, wpt); err != nil {
		return nil, nil, fmt.Errorf("validating WPT JWT: %w", err)
	}
	if len(parsedWPT.Headers) != 1 {
		return nil, nil, fmt.Errorf("WPT JWT must contain exactly one header")
	}
	if typ := parsedWPT.Headers[0]; typ.ExtraHeaders[jose.HeaderType] != wptJWTType {
		return nil, nil, fmt.Errorf("invalid WPT JWT: expected type %v, got %v", wptJWTType, typ)
	}
	// Check the WTH claim of the WPT matches the WIT
	if wpt.WTH != base64SHA256(rawWIT) {
		return nil, nil, fmt.Errorf("WPT WTH claim does not match WIT")
	}

	return wit, wpt, nil
}
