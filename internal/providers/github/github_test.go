package github_test

import (
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	github "github.com/ubuntu/authd-oidc-brokers/internal/providers/github"
)

func TestNew(t *testing.T) {
	t.Parallel()

	p := github.New()

	require.Empty(t, p, "New should return the default provider implementation with no parameters")
}

func TestAdditionalScopes(t *testing.T) {
	t.Parallel()

	p := github.New()

	require.ElementsMatch(t, []string{oidc.ScopeOfflineAccess, "user:email"}, p.AdditionalScopes(), "Github provider should require a couple of additional scopes")
}
