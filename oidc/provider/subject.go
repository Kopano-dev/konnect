package provider

import (
	"encoding/base64"

	blake2b "github.com/minio/blake2b-simd"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
)

// PublicSubjectFromAuth creates the provideds auth Subject value with the
// accociated provider. This subject can be used as URL safe value to uniquely
// identify the provided auth user with remote systems.
func (p *Provider) PublicSubjectFromAuth(auth identity.AuthRecord) (string, error) {
	authorizedScopes := auth.AuthorizedScopes()
	if ok, _ := authorizedScopes[konnect.ScopeHashedSubject]; !ok {
		// Return raw subject as is when not with ScopeHashedSubject.
		return auth.Subject(), nil
	}

	// Hash the raw subject with a konnect specific salt.
	hasher := blake2b.NewMAC(64, []byte(oidc.KonnectIDTokenSubjectSaltV1))
	hasher.Write([]byte(auth.Subject()))

	// NOTE(longsleep): URL safe encoding for subject is important since many
	// third party applications validate this with rather strict patterns.
	sub := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return sub + "@konnect", nil
}
