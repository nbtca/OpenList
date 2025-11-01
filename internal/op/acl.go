package op

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/pkg/errors"
)

// GetACLRules returns all ACL rules
func GetACLRules() ([]model.ACLRule, error) {
	return db.GetACLRules()
}

// GetACLRuleByID returns an ACL rule by its ID
func GetACLRuleByID(id uint) (*model.ACLRule, error) {
	return db.GetACLRuleByID(id)
}

// CreateACLRule creates a new ACL rule
func CreateACLRule(rule *model.ACLRule) error {
	return db.CreateACLRule(rule)
}

// UpdateACLRule updates an existing ACL rule
func UpdateACLRule(rule *model.ACLRule) error {
	return db.UpdateACLRule(rule)
}

// DeleteACLRuleByID deletes an ACL rule by its ID
func DeleteACLRuleByID(id uint) error {
	return db.DeleteACLRuleByID(id)
}

// CheckACLPermission checks if the user has the required permission for a path
func CheckACLPermission(ctx context.Context, path string, requiredPerm int32) (*model.ACLMatchedRule, error) {
	// Check if ACL is enabled
	if !isACLEnabled() {
		return nil, nil
	}

	user := ctx.Value(conf.UserKey).(*model.User)

	// Admin users bypass ACL
	if user.IsAdmin() {
		return nil, nil
	}

	normalizedPath := normalizePath(path)
	requiredPermName := getPermissionName(requiredPerm)

	// Guest users are subject to ACL
	// Get user's roles
	userRoles := getUserRoles(user)
	if len(userRoles) == 0 {
		utils.Log.Warnf("ACL denied: user=%d(%s) has no roles (path: %s, required: %s)",
			user.ID, user.Username, normalizedPath, requiredPermName)
		return nil, errors.WithStack(errs.NewACLPermissionDeniedError(
			normalizedPath,
			requiredPermName,
			userRoles,
			nil,
			"no_roles",
		))
	}

	// Get all ACL rules
	allRules, err := db.GetACLRules()
	if err != nil {
		return nil, err
	}

	// Find matching rules for user's roles
	var matchedRule *model.ACLRule

	for _, rule := range allRules {
		// Check if rule applies to any of the user's roles
		if !containsRole(userRoles, rule.Role) {
			continue
		}

		// Check if path matches the rule
		if pathMatches(normalizedPath, rule.Path) {
			if matchedRule == nil || rule.Priority > matchedRule.Priority {
				matchedRule = &rule
			}
		}
	}

	if matchedRule == nil {
		// No matching rule found, deny access
		utils.Log.Warnf("ACL denied: user=%d(%s) roles=%v no matching rule (path: %s, required: %s)",
			user.ID, user.Username, userRoles, normalizedPath, requiredPermName)
		return nil, errors.WithStack(errs.NewACLPermissionDeniedError(
			normalizedPath,
			requiredPermName,
			userRoles,
			nil,
			"no_matching_rule",
		))
	}

	// Check if the matched rule has the required permission
	if !matchedRule.HasPermission(requiredPerm) {
		utils.Log.Warnf("ACL denied: user=%d(%s) role=%s rule_id=%d insufficient permission (path: %s, rule_path: %s, has: %d, required: %s)",
			user.ID, user.Username, matchedRule.Role, matchedRule.ID, normalizedPath, matchedRule.Path, matchedRule.Permissions, requiredPermName)
		
		ruleInfo := &errs.ACLRuleInfo{
			RulePath:    matchedRule.Path,
			Role:        matchedRule.Role,
			Permissions: getPermissionNames(matchedRule.Permissions),
			Priority:    matchedRule.Priority,
		}
		
		return nil, errors.WithStack(errs.NewACLPermissionDeniedError(
			normalizedPath,
			requiredPermName,
			userRoles,
			ruleInfo,
			"insufficient_permission",
		))
	}

	utils.Log.Infof("ACL matched: user=%d(%s) role=%s rule_id=%d path=%s permissions=%d required=%d",
		user.ID, user.Username, matchedRule.Role, matchedRule.ID, normalizedPath, matchedRule.Permissions, requiredPerm)

	return &model.ACLMatchedRule{
		Rule:        matchedRule,
		Permissions: matchedRule.Permissions,
		Path:        normalizedPath,
	}, nil
}

// GetMatchedACLRule returns the matched ACL rule for a user and path (for display purposes)
func GetMatchedACLRule(ctx context.Context, path string) (*model.ACLMatchedRule, error) {
	// Check if ACL is enabled
	if !isACLEnabled() {
		return nil, nil
	}

	user := ctx.Value(conf.UserKey).(*model.User)

	// Admin users bypass ACL
	if user.IsAdmin() {
		return &model.ACLMatchedRule{
			Rule:        nil,
			Permissions: model.ACLPermRead | model.ACLPermWrite | model.ACLPermDelete | model.ACLPermManage | model.ACLPermShare | model.ACLPermDownload,
			Path:        path,
		}, nil
	}

	userRoles := getUserRoles(user)
	if len(userRoles) == 0 {
		return nil, nil
	}

	allRules, err := db.GetACLRules()
	if err != nil {
		return nil, err
	}

	var matchedRule *model.ACLRule
	normalizedPath := normalizePath(path)

	for _, rule := range allRules {
		if !containsRole(userRoles, rule.Role) {
			continue
		}

		if pathMatches(normalizedPath, rule.Path) {
			if matchedRule == nil || rule.Priority > matchedRule.Priority {
				matchedRule = &rule
			}
		}
	}

	if matchedRule == nil {
		return nil, nil
	}
	utils.Log.Infof("ACL matched (preview): user=%d(%s) role=%s rule_id=%d path=%s permissions=%d",
		user.ID, user.Username, matchedRule.Role, matchedRule.ID, normalizedPath, matchedRule.Permissions)

	return &model.ACLMatchedRule{
		Rule:        matchedRule,
		Permissions: matchedRule.Permissions,
		Path:        normalizedPath,
	}, nil
}

// Helper functions

// isACLEnabled checks if ACL is enabled by directly querying the database
// to avoid circular dependency with setting package
func isACLEnabled() bool {
	setting, err := db.GetSettingItemByKey(conf.ACLEnabled)
	if err != nil || setting == nil {
		return false
	}
	return setting.Value == "true" || setting.Value == "1"
}

func getUserRoles(user *model.User) []string {
	if user.Roles == "" {
		return []string{}
	}
	roles := strings.Split(user.Roles, ",")
	for i := range roles {
		roles[i] = strings.TrimSpace(roles[i])
	}
	return roles
}

func containsRole(roles []string, role string) bool {
	if role == "*" {
		return true
	}
	return slices.Contains(roles, role)
}

func normalizePath(path string) string {
	// Normalize path separators
	path = filepath.ToSlash(path)
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Clean the path
	path = filepath.Clean(path)
	path = filepath.ToSlash(path)
	return path
}

func pathMatches(path, pattern string) bool {
	// Normalize both paths
	path = normalizePath(path)
	pattern = normalizePath(pattern)

	// Exact match
	if path == pattern {
		return true
	}

	// Pattern with wildcard
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		// Check if path is under this directory
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	// Pattern is a parent directory
	if strings.HasPrefix(path, pattern+"/") {
		return true
	}

	return false
}

// getPermissionName returns a human-readable name for a permission bit
func getPermissionName(perm int32) string {
	switch perm {
	case model.ACLPermRead:
		return "Read"
	case model.ACLPermWrite:
		return "Write"
	case model.ACLPermDelete:
		return "Delete"
	case model.ACLPermManage:
		return "Manage"
	case model.ACLPermShare:
		return "Share"
	case model.ACLPermDownload:
		return "Download"
	default:
		return fmt.Sprintf("Unknown(%d)", perm)
	}
}

// getPermissionNames returns a list of human-readable permission names
func getPermissionNames(perms int32) []string {
	names := []string{}
	if perms&model.ACLPermRead != 0 {
		names = append(names, "Read")
	}
	if perms&model.ACLPermWrite != 0 {
		names = append(names, "Write")
	}
	if perms&model.ACLPermDelete != 0 {
		names = append(names, "Delete")
	}
	if perms&model.ACLPermManage != 0 {
		names = append(names, "Manage")
	}
	if perms&model.ACLPermShare != 0 {
		names = append(names, "Share")
	}
	if perms&model.ACLPermDownload != 0 {
		names = append(names, "Download")
	}
	return names
}
