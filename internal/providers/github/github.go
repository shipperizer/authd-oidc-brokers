// Package github is the github specific extension.
package github

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	ghapi "github.com/google/go-github/v66/github"
	"github.com/google/uuid"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/info"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/noprovider"
	"golang.org/x/oauth2"
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

// SkipIDTokenVerification caters for use cases where IDToken is not present or is not a jwt
func (p Provider) SkipIDTokenVerification() bool {
	return true
}

// Scopes returns the generic scopes required by the provider.
func (p Provider) Scopes() []string {
	return []string{"user:email"}
}

// CheckTokenScopes checks if the token has the required scopes.
func (p Provider) CheckTokenScopes(token *oauth2.Token) error {
	scopes, err := p.getTokenScopes(token)
	if err != nil {
		return err
	}

	var missingScopes []string
	for _, s := range p.Scopes() {
		if !slices.Contains(scopes, s) {
			missingScopes = append(missingScopes, s)
		}
	}
	if len(missingScopes) > 0 {
		return fmt.Errorf("missing required scopes: %s", strings.Join(missingScopes, ", "))
	}
	return nil
}

func (p Provider) getTokenScopes(token *oauth2.Token) ([]string, error) {
	scopesStr, ok := token.Extra("scope").(string)
	if !ok {
		return nil, fmt.Errorf("failed to cast token scopes to string: %v", token.Extra("scope"))
	}
	return strings.Split(scopesStr, " "), nil
}

// GetUserInfo is a no-op when no specific provider is in use.
func (p Provider) GetUserInfo(ctx context.Context, accessToken *oauth2.Token, idToken *oidc.IDToken) (info.User, error) {
	if accessToken == nil {
		return info.User{}, fmt.Errorf("access token is empty")
	}

	gh := ghapi.NewClient(nil).WithAuthToken(accessToken.AccessToken)

	user, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		return info.User{}, err
	}

	return info.NewUser(
		user.GetEmail(), // use GH login
		"",
		uuid.NewSHA1(uuid.NameSpaceURL, []byte(user.GetLogin())).String(),
		"",
		"",
		[]info.Group{},
	), nil

}
