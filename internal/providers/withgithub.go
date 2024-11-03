//go:build withgithub

package providers

import "github.com/ubuntu/authd-oidc-brokers/internal/providers/github"

// CurrentProviderInfo returns a Github provider implementation.
func CurrentProviderInfo() ProviderInfoer {
	return github.New()
}
