// Package google is the google specific extension.
package google

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ubuntu/authd-oidc-brokers/internal/consts"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/noprovider"
)

// Provider is the google provider implementation.
type Provider struct {
	noprovider.NoProvider
}

// New returns a new GoogleProvider.
func New() Provider {
	return Provider{
		NoProvider: noprovider.New(),
	}
}

// CoreConfig return the oidc.Provider implementation when autodiscovery
// is not available
func (p Provider) CoreConfig() *oidc.Provider {
	return nil
}

// SkipIDTokenVerification caters for use cases where IDToken is not present or is not a jwt
func (p Provider) SkipIDTokenVerification() bool {
	return false
}

// Scopes returns the generic scopes required by the provider.
// Note that we do not return oidc.ScopeOfflineAccess, as for TV/limited input devices, the API call will fail as not
// supported by this application type. However, the refresh token will be acquired and is functional to refresh without
// user interaction.
// If we start to support other kinds of applications, we should revisit this.
// More info on https://developers.google.com/identity/protocols/oauth2/limited-input-device#allowedscopes.
func (p Provider) Scopes() []string {
	return consts.DefaultScopes
}
