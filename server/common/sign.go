package common

import (
	stdpath "path"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/gin-gonic/gin"
)

func Sign(obj model.Obj, parent string, encrypt bool) string {
	if obj.IsDir() || (!encrypt && !setting.GetBool(conf.SignAll)) {
		return ""
	}
	return sign.Sign(stdpath.Join(parent, obj.GetName()))
}

// SignWithUser 生成包含用户信息的签名
func SignWithUser(obj model.Obj, parent string, encrypt bool, user *model.User) string {
	if obj.IsDir() || (!encrypt && !setting.GetBool(conf.SignAll)) {
		return ""
	}
	return sign.SignWithUser(stdpath.Join(parent, obj.GetName()), user)
}

// SignPathWithContext 从 Context 中获取用户并生成包含用户信息的签名
func SignPathWithContext(c *gin.Context, path string) string {
	user, exists := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !exists || user == nil {
		return sign.Sign(path)
	}
	return sign.SignWithUser(path, user)
}
