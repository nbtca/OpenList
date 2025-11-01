package common

import (
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/gin-gonic/gin"
)

// CheckACL checks if the user has the required ACL permission for a path
// Returns nil if check passes, error otherwise
func CheckACL(c *gin.Context, path string, requiredPerm int32) error {
	matched, err := op.CheckACLPermission(c.Request.Context(), path, requiredPerm)
	if err != nil {
		return err
	}
	// If matched is nil, ACL is disabled or user is admin - allow access
	if matched == nil {
		return nil
	}
	return nil
}

// HasACLPermission checks if the user has a specific ACL permission for a path
// Returns true if the user has permission or ACL is disabled
func HasACLPermission(c *gin.Context, path string, requiredPerm int32) bool {
	err := CheckACL(c, path, requiredPerm)
	return err == nil
}

// GetACLPermissions returns the ACL permissions for a user and path
// Returns full permissions if ACL is disabled or user is admin
func GetACLPermissions(c *gin.Context, path string) int32 {
	matched, err := op.GetMatchedACLRule(c.Request.Context(), path)
	if err != nil {
		return 0
	}
	if matched == nil {
		// ACL disabled or admin - return all permissions
		return model.ACLPermRead | model.ACLPermWrite | model.ACLPermDelete | 
		       model.ACLPermManage | model.ACLPermShare | model.ACLPermDownload
	}
	return matched.Permissions
}
