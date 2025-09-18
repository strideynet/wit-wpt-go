package wit

import (
	"crypto"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type WIT struct {
	// ID is the SPIFFE ID of the WIT-SVID
	ID spiffeid.ID `json:"sub"`
	// PrivateKey is the private key for the WIT-SVID.
	// This will only be present for a "local" SVID (e.g. one that the workload
	// possesses)
	PrivateKey crypto.Signer
	// TODO: probably need some custom stuff here to marshal this as expected.
	PublicKey crypto.PublicKey `json:"cnf"`
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string
	// Expiry is the expiration time of the WIT-SVID as present in the `exp`
	// claim.
	Expiry time.Time `json:"exp"`
	// IssuedAt is the time that the WIT-SVID was issued as in the `iat` claim.
	IssuedAt time.Time `json:"iat"`
}

type WPT struct {
}
