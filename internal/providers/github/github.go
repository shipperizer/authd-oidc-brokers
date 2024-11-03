// Package github is the github specific extension.
package github

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/noprovider"
	"golang.org/x/oauth2/endpoints"
)

// Provider is the github provider implementation.
type Provider struct {
	noprovider.NoProvider
}

// New returns a new github Provider.
func New() Provider {
	return Provider{
		NoProvider: noprovider.New(),
	}
}

// CoreConfig return the oidc.Provider implementation when autodiscovery
// is not available
func (p Provider) CoreConfig() *oidc.Provider {
	ghEndpoint := endpoints.GitHub

	config := oidc.ProviderConfig{
		AuthURL:       ghEndpoint.AuthURL,
		TokenURL:      ghEndpoint.TokenURL,
		DeviceAuthURL: ghEndpoint.DeviceAuthURL,
		IssuerURL:     ghEndpoint.TokenURL,
	}

	return config.NewProvider(context.TODO())
}

// AdditionalScopes returns the generic scopes required by the provider.
func (Provider) AdditionalScopes() []string {
	return []string{oidc.ScopeOfflineAccess, "user:email"}
}
