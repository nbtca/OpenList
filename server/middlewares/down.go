package middlewares

import (
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func PathParse(c *gin.Context) {
	rawPath := parsePath(c.Param("path"))
	common.GinWithValue(c, conf.PathKey, rawPath)
	c.Next()
}

func Down(verifyFunc func(string, string) error) func(c *gin.Context) {
	return func(c *gin.Context) {
		rawPath := c.Request.Context().Value(conf.PathKey).(string)
		meta, err := op.GetNearestMeta(rawPath)
		if err != nil {
			if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
				common.ErrorPage(c, err, 500, true)
				return
			}
		}
		common.GinWithValue(c, conf.MetaKey, meta)

		// verify sign and try to extract user
		if needSign(meta, rawPath) {
			s := c.Query("sign")
			signStr := strings.TrimSuffix(s, "/")

			// 首先使用旧的验证方法
			err = verifyFunc(rawPath, signStr)
			if err != nil {
				common.ErrorPage(c, err, 401)
				c.Abort()
				return
			}

			// 尝试从签名中提取用户信息（如果是新格式）
			userInfo, err := sign.VerifyAndExtractUser(rawPath, signStr)
			if err == nil && userInfo != nil {
				// 签名包含用户信息，加载用户
				user, err := op.GetUserById(userInfo.ID)
				if err != nil {
					log.Warnf("Failed to get user by id from sign: %v", err)
					// 用户不存在，使用 guest
					guest, err := op.GetGuest()
					if err != nil {
						common.ErrorPage(c, err, 500)
						c.Abort()
						return
					}
					common.GinWithValue(c, conf.UserKey, guest)
				} else if user.PwdTS != userInfo.PwdTS {
					log.Warnf("Password timestamp mismatch for user %s, sign may be outdated", user.Username)
					// 密码已更改，使用 guest
					guest, err := op.GetGuest()
					if err != nil {
						common.ErrorPage(c, err, 500)
						c.Abort()
						return
					}
					common.GinWithValue(c, conf.UserKey, guest)
				} else {
					// 用户有效，设置到 Context
					common.GinWithValue(c, conf.UserKey, user)
					log.Debugf("User extracted from sign: %+v", user.Username)
				}
			} else {
				// 旧格式签名或提取失败，使用 guest
				guest, err := op.GetGuest()
				if err != nil {
					common.ErrorPage(c, err, 500)
					c.Abort()
					return
				}
				common.GinWithValue(c, conf.UserKey, guest)
			}
		} else {
			// 不需要签名，使用 guest
			guest, err := op.GetGuest()
			if err != nil {
				common.ErrorPage(c, err, 500)
				c.Abort()
				return
			}
			common.GinWithValue(c, conf.UserKey, guest)
		}

		c.Next()
	}
}

// DownWithUserExtraction 验证签名并从签名中提取用户信息设置到 Context
func DownWithUserExtraction(c *gin.Context) {
	rawPath := c.Request.Context().Value(conf.PathKey).(string)
	meta, err := op.GetNearestMeta(rawPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorPage(c, err, 500, true)
			return
		}
	}
	common.GinWithValue(c, conf.MetaKey, meta)

	// verify sign and extract user
	if needSign(meta, rawPath) {
		s := c.Query("sign")
		userInfo, err := sign.VerifyAndExtractUser(rawPath, strings.TrimSuffix(s, "/"))
		if err != nil {
			common.ErrorPage(c, err, 401)
			c.Abort()
			return
		}

		// 如果签名中包含用户信息，从数据库加载完整用户并设置到 Context
		if userInfo != nil {
			user, err := op.GetUserById(userInfo.ID)
			if err != nil {
				log.Warnf("Failed to get user by id from sign: %v", err)
				// 用户不存在或已被删除，使用 guest
				guest, err := op.GetGuest()
				if err != nil {
					common.ErrorPage(c, err, 500)
					c.Abort()
					return
				}
				common.GinWithValue(c, conf.UserKey, guest)
			} else {
				// 验证密码时间戳，确保密码未被修改
				if user.PwdTS != userInfo.PwdTS {
					log.Warnf("Password timestamp mismatch for user %s, sign may be outdated", user.Username)
					// 密码已更改，签名失效，使用 guest
					guest, err := op.GetGuest()
					if err != nil {
						common.ErrorPage(c, err, 500)
						c.Abort()
						return
					}
					common.GinWithValue(c, conf.UserKey, guest)
				} else {
					// 验证通过，设置用户
					common.GinWithValue(c, conf.UserKey, user)
					log.Debugf("User extracted from sign: %+v", user.Username)
				}
			}
		} else {
			// 旧格式签名，没有用户信息，使用 guest
			guest, err := op.GetGuest()
			if err != nil {
				common.ErrorPage(c, err, 500)
				c.Abort()
				return
			}
			common.GinWithValue(c, conf.UserKey, guest)
		}
	} else {
		// 不需要签名，使用 guest 用户
		guest, err := op.GetGuest()
		if err != nil {
			common.ErrorPage(c, err, 500)
			c.Abort()
			return
		}
		common.GinWithValue(c, conf.UserKey, guest)
	}

	c.Next()
}

// TODO: implement
// path maybe contains # ? etc.
func parsePath(path string) string {
	return utils.FixAndCleanPath(path)
}

func needSign(meta *model.Meta, path string) bool {
	if setting.GetBool(conf.SignAll) {
		return true
	}
	if common.IsStorageSignEnabled(path) {
		return true
	}
	if meta == nil || meta.Password == "" {
		return false
	}
	if !meta.PSub && path != meta.Path {
		return false
	}
	return true
}
