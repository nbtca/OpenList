package handles

import (
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

type ACLRuleReq struct {
	Role        string `json:"role" binding:"required"`
	Path        string `json:"path" binding:"required"`
	Permissions int32  `json:"permissions"`
	Priority    int    `json:"priority"`
}

// ListACLRules lists all ACL rules
func ListACLRules(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !user.IsAdmin() {
		common.ErrorStrResp(c, "permission denied", 403)
		return
	}
	rules, err := op.GetACLRules()
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, rules)
}

// GetACLRule gets a specific ACL rule
func GetACLRule(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !user.IsAdmin() {
		common.ErrorStrResp(c, "permission denied", 403)
		return
	}
	var req common.IDReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	rule, err := op.GetACLRuleByID(req.ID)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, rule)
}

// CreateACLRule creates a new ACL rule
func CreateACLRule(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !user.IsAdmin() {
		common.ErrorStrResp(c, "permission denied", 403)
		return
	}
	var req ACLRuleReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	rule := &model.ACLRule{
		Role:        req.Role,
		Path:        req.Path,
		Permissions: req.Permissions,
		Priority:    req.Priority,
	}
	if err := op.CreateACLRule(rule); err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, rule)
}

// UpdateACLRule updates an existing ACL rule
func UpdateACLRule(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !user.IsAdmin() {
		common.ErrorStrResp(c, "permission denied", 403)
		return
	}
	var req model.ACLRule
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	if err := op.UpdateACLRule(&req); err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, req)
}

// DeleteACLRule deletes an ACL rule
func DeleteACLRule(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !user.IsAdmin() {
		common.ErrorStrResp(c, "permission denied", 403)
		return
	}
	var req common.IDReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	if err := op.DeleteACLRuleByID(req.ID); err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c)
}

// GetPathACLInfo returns ACL information for a specific path
func GetPathACLInfo(c *gin.Context) {
	var req struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	
	matched, err := op.GetMatchedACLRule(c.Request.Context(), req.Path)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	
	common.SuccessResp(c, matched)
}
