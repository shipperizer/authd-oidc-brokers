//go:build !withgoogle && !withmsentraid && !withgithub

package providers

import (
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/noprovider"
)

// CurrentProviderInfo returns a generic oidc provider implementation.
func CurrentProviderInfo() ProviderInfoer {
	return noprovider.New()
}
