package errs

import (
	"errors"
	"fmt"
)

var (
	PermissionDenied = errors.New("permission denied")
)

// ACLPermissionDeniedError represents a detailed ACL permission denied error
type ACLPermissionDeniedError struct {
	Path             string
	RequiredPerm     string
	UserRoles        []string
	MatchedRule      *ACLRuleInfo
	Reason           string
}

// ACLRuleInfo contains information about a matched ACL rule
type ACLRuleInfo struct {
	RulePath    string
	Role        string
	Permissions []string
	Priority    int
}

func (e *ACLPermissionDeniedError) Error() string {
	if e.Reason == "no_roles" {
		return fmt.Sprintf("permission denied: user has no roles assigned (path: %s, required: %s)", 
			e.Path, e.RequiredPerm)
	}
	
	if e.Reason == "no_matching_rule" {
		return fmt.Sprintf("permission denied: no ACL rule matches (path: %s, user roles: %v, required: %s)", 
			e.Path, e.UserRoles, e.RequiredPerm)
	}
	
	if e.Reason == "insufficient_permission" && e.MatchedRule != nil {
		return fmt.Sprintf("permission denied: insufficient permissions (path: %s, required: %s, matched rule: role=%s path=%s permissions=%v priority=%d)", 
			e.Path, e.RequiredPerm, e.MatchedRule.Role, e.MatchedRule.RulePath, 
			e.MatchedRule.Permissions, e.MatchedRule.Priority)
	}
	
	return fmt.Sprintf("permission denied: %s (path: %s)", e.Reason, e.Path)
}

// NewACLPermissionDeniedError creates a new ACL permission denied error
func NewACLPermissionDeniedError(path, requiredPerm string, userRoles []string, matchedRule *ACLRuleInfo, reason string) *ACLPermissionDeniedError {
	return &ACLPermissionDeniedError{
		Path:         path,
		RequiredPerm: requiredPerm,
		UserRoles:    userRoles,
		MatchedRule:  matchedRule,
		Reason:       reason,
	}
}
