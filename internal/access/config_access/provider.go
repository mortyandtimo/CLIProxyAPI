package configaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

// Register ensures the config-access provider is available to the access manager.
func Register(cfg *sdkconfig.SDKConfig) {
	if cfg == nil {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	keys, keyRules := normalizeKeyEntries(cfg.APIKeys, cfg.APIKeyEntries)
	if len(keys) == 0 {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	sdkaccess.RegisterProvider(
		sdkaccess.AccessProviderTypeConfigAPIKey,
		newProvider(sdkaccess.DefaultAccessProviderName, keys, keyRules),
	)
}

type keyRule struct {
	pools    []string
	strategy string
}

type provider struct {
	name     string
	keys     map[string]struct{}
	keyRules map[string]keyRule
}

func newProvider(name string, keys []string, keyRules map[string]keyRule) *provider {
	providerName := strings.TrimSpace(name)
	if providerName == "" {
		providerName = sdkaccess.DefaultAccessProviderName
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}
	return &provider{name: providerName, keys: keySet, keyRules: keyRules}
}

func (p *provider) Identifier() string {
	if p == nil || p.name == "" {
		return sdkaccess.DefaultAccessProviderName
	}
	return p.name
}

func (p *provider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if p == nil {
		return nil, sdkaccess.NewNotHandledError()
	}
	if len(p.keys) == 0 {
		return nil, sdkaccess.NewNotHandledError()
	}
	authHeader := r.Header.Get("Authorization")
	authHeaderGoogle := r.Header.Get("X-Goog-Api-Key")
	authHeaderAnthropic := r.Header.Get("X-Api-Key")
	queryKey := ""
	queryAuthToken := ""
	if r.URL != nil {
		queryKey = r.URL.Query().Get("key")
		queryAuthToken = r.URL.Query().Get("auth_token")
	}
	if authHeader == "" && authHeaderGoogle == "" && authHeaderAnthropic == "" && queryKey == "" && queryAuthToken == "" {
		return nil, sdkaccess.NewNoCredentialsError()
	}

	apiKey := extractBearerToken(authHeader)

	candidates := []struct {
		value  string
		source string
	}{
		{apiKey, "authorization"},
		{authHeaderGoogle, "x-goog-api-key"},
		{authHeaderAnthropic, "x-api-key"},
		{queryKey, "query-key"},
		{queryAuthToken, "query-auth-token"},
	}

	for _, candidate := range candidates {
		if candidate.value == "" {
			continue
		}
		if _, ok := p.keys[candidate.value]; ok {
			metadata := map[string]string{
				"source": candidate.source,
			}
			if rule, ok := p.keyRules[candidate.value]; ok {
				if len(rule.pools) > 0 {
					if data, err := json.Marshal(rule.pools); err == nil {
						metadata["auth_file_pools"] = string(data)
					}
				}
				if strings.TrimSpace(rule.strategy) != "" {
					metadata["auth_file_pool_strategy"] = strings.TrimSpace(rule.strategy)
				}
			}
			return &sdkaccess.Result{
				Provider:  p.Identifier(),
				Principal: candidate.value,
				Metadata:  metadata,
			}, nil
		}
	}

	return nil, sdkaccess.NewInvalidCredentialError()
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return header
	}
	return strings.TrimSpace(parts[1])
}

func normalizeKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if _, exists := seen[trimmedKey]; exists {
			continue
		}
		seen[trimmedKey] = struct{}{}
		normalized = append(normalized, trimmedKey)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizePools(pools []string) []string {
	if len(pools) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(pools))
	out := make([]string, 0, len(pools))
	for _, pool := range pools {
		trimmed := strings.ToLower(strings.TrimSpace(pool))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeKeyEntries(keys []string, entries []sdkconfig.APIKeyEntry) ([]string, map[string]keyRule) {
	base := normalizeKeys(keys)
	if len(entries) == 0 {
		return base, map[string]keyRule{}
	}
	seen := make(map[string]struct{}, len(base)+len(entries))
	out := make([]string, 0, len(base)+len(entries))
	for _, key := range base {
		seen[key] = struct{}{}
		out = append(out, key)
	}
	keyRules := make(map[string]keyRule)
	for _, entry := range entries {
		trimmedKey := strings.TrimSpace(entry.Key)
		if trimmedKey == "" {
			continue
		}
		if _, ok := seen[trimmedKey]; !ok {
			seen[trimmedKey] = struct{}{}
			out = append(out, trimmedKey)
		}
		rule := keyRule{pools: normalizePools(entry.AuthFilePools), strategy: strings.ToLower(strings.TrimSpace(entry.PoolStrategy))}
		if len(rule.pools) > 0 || rule.strategy != "" {
			keyRules[trimmedKey] = rule
		}
	}
	if len(out) == 0 {
		return nil, keyRules
	}
	return out, keyRules
}
