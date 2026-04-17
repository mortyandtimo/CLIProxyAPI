package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
type RoundRobinSelector struct {
	mu      sync.Mutex
	cursors map[string]int
	maxKeys int
}

// FillFirstSelector selects the first available credential (deterministic ordering).
// This "burns" one account before moving to the next, which can help stagger
// rolling-window subscription caps (e.g. chat message limits).
type FillFirstSelector struct {
	mu      sync.Mutex
	cursors map[string]int
	maxKeys int
}

type blockReason int

const (
	blockReasonNone blockReason = iota
	blockReasonCooldown
	blockReasonDisabled
	blockReasonOther
)

type modelCooldownError struct {
	model    string
	resetIn  time.Duration
	provider string
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
	}
}

func (e *modelCooldownError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	message := fmt.Sprintf("All credentials for model %s are cooling down", modelName)
	if e.provider != "" {
		message = fmt.Sprintf("%s via provider %s", message, e.provider)
	}
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := e.resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	errorBody := map[string]any{
		"code":          "model_cooldown",
		"message":       message,
		"model":         e.model,
		"reset_time":    displayDuration.String(),
		"reset_seconds": resetSeconds,
	}
	if e.provider != "" {
		errorBody["provider"] = e.provider
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

func (e *modelCooldownError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *modelCooldownError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}

func authPriority(auth *Auth) int {
	if auth == nil || auth.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(auth.Attributes["priority"])
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return parsed
}

func authWeight(auth *Auth) int {
	if auth == nil {
		return 1
	}
	if auth.Attributes != nil {
		raw := strings.TrimSpace(auth.Attributes["weight"])
		if raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	if auth.Metadata != nil {
		if raw, ok := auth.Metadata["weight"]; ok {
			switch v := raw.(type) {
			case int:
				if v > 0 {
					return v
				}
			case float64:
				if int(v) > 0 {
					return int(v)
				}
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && parsed > 0 {
					return parsed
				}
			}
		}
	}
	return 1
}

func clientPoolsFromMetadata(meta map[string]any) []string {
	if len(meta) == 0 {
		return nil
	}
	raw, ok := meta["auth_file_pools"]
	if !ok || raw == nil {
		return nil
	}
	var values []string
	switch v := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		if strings.HasPrefix(trimmed, "[") {
			_ = json.Unmarshal([]byte(trimmed), &values)
		} else {
			values = strings.FieldsFunc(trimmed, func(r rune) bool { return r == ',' || r == '\n' || r == '\t' })
		}
	case []string:
		values = append(values, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	default:
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
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

func poolStrategyFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta["auth_file_pool_strategy"]
	if !ok || raw == nil {
		return ""
	}
	if s, ok := raw.(string); ok {
		return strings.ToLower(strings.TrimSpace(s))
	}
	return ""
}

func authPools(auth *Auth) []string {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, ok := auth.Metadata["pools"]
	if !ok || raw == nil {
		return nil
	}
	values := make([]string, 0)
	switch v := raw.(type) {
	case []string:
		values = append(values, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		if strings.HasPrefix(trimmed, "[") {
			_ = json.Unmarshal([]byte(trimmed), &values)
		} else {
			values = strings.FieldsFunc(trimmed, func(r rune) bool { return r == ',' || r == '\n' || r == '\t' })
		}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
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

func authPoolGroups(auth *Auth) map[string]string {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, ok := auth.Metadata["pool_groups"]
	if !ok || raw == nil {
		return nil
	}
	groups := make(map[string]string)
	switch v := raw.(type) {
	case map[string]string:
		for pool, group := range v {
			trimmedPool := strings.ToLower(strings.TrimSpace(pool))
			trimmedGroup := strings.ToLower(strings.TrimSpace(group))
			if trimmedPool == "" || trimmedGroup == "" {
				continue
			}
			groups[trimmedPool] = trimmedGroup
		}
	case map[string]any:
		for pool, group := range v {
			groupName, ok := group.(string)
			if !ok {
				continue
			}
			trimmedPool := strings.ToLower(strings.TrimSpace(pool))
			trimmedGroup := strings.ToLower(strings.TrimSpace(groupName))
			if trimmedPool == "" || trimmedGroup == "" {
				continue
			}
			groups[trimmedPool] = trimmedGroup
		}
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		decoded := make(map[string]string)
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			return nil
		}
		for pool, group := range decoded {
			trimmedPool := strings.ToLower(strings.TrimSpace(pool))
			trimmedGroup := strings.ToLower(strings.TrimSpace(group))
			if trimmedPool == "" || trimmedGroup == "" {
				continue
			}
			groups[trimmedPool] = trimmedGroup
		}
	default:
		return nil
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

func matchedPoolForAuth(auth *Auth, clientPools []string) string {
	pools := authPools(auth)
	if len(pools) == 0 {
		return ""
	}
	if len(clientPools) == 0 {
		return pools[0]
	}
	available := make(map[string]struct{}, len(pools))
	for _, pool := range pools {
		available[pool] = struct{}{}
	}
	for _, pool := range clientPools {
		if _, ok := available[pool]; ok {
			return pool
		}
	}
	return ""
}

func groupBySelectedPoolSubgroup(auths []*Auth, clientPools []string) (map[string][]*Auth, []string, string) {
	if len(auths) == 0 || len(clientPools) != 1 {
		return nil, nil, ""
	}
	selectedPool := strings.ToLower(strings.TrimSpace(clientPools[0]))
	if selectedPool == "" {
		return nil, nil, ""
	}
	groups := make(map[string][]*Auth)
	hasNamedGroup := false
	for _, auth := range auths {
		if matchedPoolForAuth(auth, clientPools) != selectedPool {
			continue
		}
		groupName := ""
		if authGroups := authPoolGroups(auth); len(authGroups) > 0 {
			groupName = authGroups[selectedPool]
		}
		if groupName != "" {
			hasNamedGroup = true
		}
		groups[groupName] = append(groups[groupName], auth)
	}
	if !hasNamedGroup || len(groups) <= 1 {
		return nil, nil, selectedPool
	}
	order := make([]string, 0, len(groups))
	for group := range groups {
		order = append(order, group)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i] == "" {
			return order[j] != ""
		}
		if order[j] == "" {
			return false
		}
		return order[i] < order[j]
	})
	return groups, order, selectedPool
}

func filterAuthsByPools(auths []*Auth, clientPools []string) []*Auth {
	if len(clientPools) == 0 || len(auths) == 0 {
		return auths
	}
	allowed := make(map[string]struct{}, len(clientPools))
	for _, pool := range clientPools {
		allowed[pool] = struct{}{}
	}
	out := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		pools := authPools(auth)
		if len(pools) == 0 {
			continue
		}
		for _, pool := range pools {
			if _, ok := allowed[pool]; ok {
				out = append(out, auth)
				break
			}
		}
	}
	return out
}

func pickWeightedAuth(available []*Auth) *Auth {
	if len(available) == 0 {
		return nil
	}
	total := 0
	weights := make([]int, len(available))
	for i, auth := range available {
		w := authWeight(auth)
		if w <= 0 {
			w = 1
		}
		weights[i] = w
		total += w
	}
	if total <= 0 {
		return available[0]
	}
	pick := rand.IntN(total)
	running := 0
	for i, auth := range available {
		running += weights[i]
		if pick < running {
			return auth
		}
	}
	return available[len(available)-1]
}

func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(model)
	modelName := strings.TrimSpace(parsed.ModelName)
	if modelName == "" {
		return model
	}
	return modelName
}

func authWebsocketsEnabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

func preferCodexWebsocketAuths(ctx context.Context, provider string, available []*Auth) []*Auth {
	if len(available) == 0 {
		return available
	}
	if !cliproxyexecutor.DownstreamWebsocket(ctx) {
		return available
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return available
	}

	wsEnabled := make([]*Auth, 0, len(available))
	for i := 0; i < len(available); i++ {
		candidate := available[i]
		if authWebsocketsEnabled(candidate) {
			wsEnabled = append(wsEnabled, candidate)
		}
	}
	if len(wsEnabled) > 0 {
		return wsEnabled
	}
	return available
}

func collectAvailableByPriority(auths []*Auth, model string, now time.Time) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		blocked, reason, next := isAuthBlockedForModel(candidate, model, now)
		if !blocked {
			priority := authPriority(candidate)
			available[priority] = append(available[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
			if !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
				earliest = next
			}
		}
	}
	return available, cooldownCount, earliest
}

func getAvailableAuths(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(auths, model, now)
	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(model, providerForError, resetIn)
		}
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	bestPriority := 0
	found := false
	for priority := range availableByPriority {
		if !found || priority > bestPriority {
			bestPriority = priority
			found = true
		}
	}

	available := availableByPriority[bestPriority]
	if len(available) > 1 {
		sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	}
	return available, nil
}

// Pick selects the next available auth for the provider in a round-robin manner.
// For gemini-cli virtual auths (identified by the gemini_virtual_parent attribute),
// a two-level round-robin is used: first cycling across credential groups (parent
// accounts), then cycling within each group's project auths.
func (s *RoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	clientPools := clientPoolsFromMetadata(opts.Metadata)
	auths = filterAuthsByPools(auths, clientPools)
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	strategy := poolStrategyFromMetadata(opts.Metadata)
	key := provider + ":" + canonicalModelKey(model)
	if strategy == "fill-first" || strategy == "failover" {
		if groups, order, selectedPool := groupBySelectedPoolSubgroup(available, clientPools); len(order) > 1 {
			s.mu.Lock()
			if s.cursors == nil {
				s.cursors = make(map[string]int)
			}
			limit := s.maxKeys
			if limit <= 0 {
				limit = 4096
			}
			picked := s.pickSubgroupLocked(key, selectedPool, groups, order, limit, strategy)
			s.mu.Unlock()
			return picked, nil
		}
		return available[0], nil
	}
	if strategy == "weighted" {
		if groups, order, selectedPool := groupBySelectedPoolSubgroup(available, clientPools); len(order) > 1 {
			s.mu.Lock()
			if s.cursors == nil {
				s.cursors = make(map[string]int)
			}
			limit := s.maxKeys
			if limit <= 0 {
				limit = 4096
			}
			picked := s.pickSubgroupLocked(key, selectedPool, groups, order, limit, strategy)
			s.mu.Unlock()
			return picked, nil
		}
		return pickWeightedAuth(available), nil
	}

	s.mu.Lock()
	if s.cursors == nil {
		s.cursors = make(map[string]int)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if groups, order, selectedPool := groupBySelectedPoolSubgroup(available, clientPools); len(order) > 1 {
		picked := s.pickSubgroupLocked(key, selectedPool, groups, order, limit, strategy)
		s.mu.Unlock()
		return picked, nil
	}
	picked := s.pickRoundRobinLocked(key, available, limit)
	s.mu.Unlock()
	return picked, nil
}

func (s *RoundRobinSelector) pickSubgroupLocked(key, pool string, groups map[string][]*Auth, order []string, limit int, strategy string) *Auth {
	if len(order) == 0 {
		return nil
	}
	groupKey := key + "::pool:" + pool + "::group"
	s.ensureCursorKey(groupKey, limit)
	groupIndex := s.cursors[groupKey]
	if groupIndex >= 2_147_483_640 {
		groupIndex = 0
	}
	s.cursors[groupKey] = groupIndex + 1
	selectedGroup := order[groupIndex%len(order)]
	members := groups[selectedGroup]
	if len(members) == 0 {
		return nil
	}
	subgroupKey := selectedGroup
	if subgroupKey == "" {
		subgroupKey = "__ungrouped"
	}
	namespace := key + "::pool:" + pool + "::subgroup:" + subgroupKey
	switch strategy {
	case "fill-first", "failover":
		return members[0]
	case "weighted":
		return pickWeightedAuth(members)
	default:
		return s.pickRoundRobinLocked(namespace, members, limit)
	}
}

func (s *RoundRobinSelector) pickRoundRobinLocked(key string, available []*Auth, limit int) *Auth {
	if len(available) == 0 {
		return nil
	}
	// Check if any available auth has gemini_virtual_parent attribute,
	// indicating gemini-cli virtual auths that should use credential-level polling.
	groups, parentOrder := groupByVirtualParent(available)
	if len(parentOrder) > 1 {
		// Two-level round-robin: first select a credential group, then pick within it.
		groupKey := key + "::group"
		s.ensureCursorKey(groupKey, limit)
		if _, exists := s.cursors[groupKey]; !exists {
			// Seed with a random initial offset so the starting credential is randomized.
			s.cursors[groupKey] = rand.IntN(len(parentOrder))
		}
		groupIndex := s.cursors[groupKey]
		if groupIndex >= 2_147_483_640 {
			groupIndex = 0
		}
		s.cursors[groupKey] = groupIndex + 1

		selectedParent := parentOrder[groupIndex%len(parentOrder)]
		group := groups[selectedParent]

		// Second level: round-robin within the selected credential group.
		innerKey := key + "::cred:" + selectedParent
		s.ensureCursorKey(innerKey, limit)
		innerIndex := s.cursors[innerKey]
		if innerIndex >= 2_147_483_640 {
			innerIndex = 0
		}
		s.cursors[innerKey] = innerIndex + 1
		return group[innerIndex%len(group)]
	}

	// Flat round-robin for non-grouped auths (original behavior).
	s.ensureCursorKey(key, limit)
	index := s.cursors[key]
	if index >= 2_147_483_640 {
		index = 0
	}
	s.cursors[key] = index + 1
	return available[index%len(available)]
}

func (s *FillFirstSelector) pickSubgroupLocked(key, pool string, groups map[string][]*Auth, order []string, limit int, strategy string) *Auth {
	if len(order) == 0 {
		return nil
	}
	groupKey := key + "::pool:" + pool + "::group"
	s.ensureCursorKey(groupKey, limit)
	groupIndex := s.cursors[groupKey]
	if groupIndex >= 2_147_483_640 {
		groupIndex = 0
	}
	s.cursors[groupKey] = groupIndex + 1
	selectedGroup := order[groupIndex%len(order)]
	members := groups[selectedGroup]
	if len(members) == 0 {
		return nil
	}
	if strategy == "weighted" {
		return pickWeightedAuth(members)
	}
	return members[0]
}

// ensureCursorKey ensures the cursor map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureCursorKey(key string, limit int) {
	if _, ok := s.cursors[key]; !ok && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

func (s *FillFirstSelector) ensureCursorKey(key string, limit int) {
	if _, ok := s.cursors[key]; !ok && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

// groupByVirtualParent groups auths by their gemini_virtual_parent attribute.
// Returns a map of parentID -> auths and a sorted slice of parent IDs for stable iteration.
// Only auths with a non-empty gemini_virtual_parent are grouped; if any auth lacks
// this attribute, nil/nil is returned so the caller falls back to flat round-robin.
func groupByVirtualParent(auths []*Auth) (map[string][]*Auth, []string) {
	if len(auths) == 0 {
		return nil, nil
	}
	groups := make(map[string][]*Auth)
	for _, a := range auths {
		parent := ""
		if a.Attributes != nil {
			parent = strings.TrimSpace(a.Attributes["gemini_virtual_parent"])
		}
		if parent == "" {
			// Non-virtual auth present; fall back to flat round-robin.
			return nil, nil
		}
		groups[parent] = append(groups[parent], a)
	}
	// Collect parent IDs in sorted order for stable cursor indexing.
	parentOrder := make([]string, 0, len(groups))
	for p := range groups {
		parentOrder = append(parentOrder, p)
	}
	sort.Strings(parentOrder)
	return groups, parentOrder
}

// Pick selects the first available auth for the provider in a deterministic manner.
func (s *FillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	clientPools := clientPoolsFromMetadata(opts.Metadata)
	auths = filterAuthsByPools(auths, clientPools)
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	strategy := poolStrategyFromMetadata(opts.Metadata)
	if strategy == "weighted" {
		if groups, order, selectedPool := groupBySelectedPoolSubgroup(available, clientPools); len(order) > 1 {
			s.mu.Lock()
			if s.cursors == nil {
				s.cursors = make(map[string]int)
			}
			limit := s.maxKeys
			if limit <= 0 {
				limit = 4096
			}
			picked := s.pickSubgroupLocked(provider+":"+canonicalModelKey(model), selectedPool, groups, order, limit, strategy)
			s.mu.Unlock()
			return picked, nil
		}
		return pickWeightedAuth(available), nil
	}
	if groups, order, selectedPool := groupBySelectedPoolSubgroup(available, clientPools); len(order) > 1 {
		s.mu.Lock()
		if s.cursors == nil {
			s.cursors = make(map[string]int)
		}
		limit := s.maxKeys
		if limit <= 0 {
			limit = 4096
		}
		picked := s.pickSubgroupLocked(provider+":"+canonicalModelKey(model), selectedPool, groups, order, limit, "fill-first")
		s.mu.Unlock()
		return picked, nil
	}
	return available[0], nil
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true, blockReasonDisabled, time.Time{}
	}
	if model != "" {
		if len(auth.ModelStates) > 0 {
			state, ok := auth.ModelStates[model]
			if (!ok || state == nil) && model != "" {
				baseModel := canonicalModelKey(model)
				if baseModel != "" && baseModel != model {
					state, ok = auth.ModelStates[baseModel]
				}
			}
			if ok && state != nil {
				if state.Status == StatusDisabled {
					return true, blockReasonDisabled, time.Time{}
				}
				if state.Unavailable {
					if state.NextRetryAfter.IsZero() {
						return false, blockReasonNone, time.Time{}
					}
					if state.NextRetryAfter.After(now) {
						next := state.NextRetryAfter
						if !state.Quota.NextRecoverAt.IsZero() && state.Quota.NextRecoverAt.After(now) {
							next = state.Quota.NextRecoverAt
						}
						if next.Before(now) {
							next = now
						}
						if state.Quota.Exceeded {
							return true, blockReasonCooldown, next
						}
						return true, blockReasonOther, next
					}
				}
				return false, blockReasonNone, time.Time{}
			}
		}
		return false, blockReasonNone, time.Time{}
	}
	if auth.Unavailable && auth.NextRetryAfter.After(now) {
		next := auth.NextRetryAfter
		if !auth.Quota.NextRecoverAt.IsZero() && auth.Quota.NextRecoverAt.After(now) {
			next = auth.Quota.NextRecoverAt
		}
		if next.Before(now) {
			next = now
		}
		if auth.Quota.Exceeded {
			return true, blockReasonCooldown, next
		}
		return true, blockReasonOther, next
	}
	return false, blockReasonNone, time.Time{}
}
