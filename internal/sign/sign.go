package sign

import (
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/sign"
)

var once sync.Once
var instance sign.Sign

func Sign(data string) string {
	expire := setting.GetInt(conf.LinkExpiration, 0)
	if expire == 0 {
		return NotExpired(data)
	} else {
		return WithDuration(data, time.Duration(expire)*time.Hour)
	}
}

// SignWithUser 创建包含用户信息的签名
func SignWithUser(data string, user *model.User) string {
	if user == nil {
		return Sign(data)
	}

	userInfo := &sign.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		PwdTS:    user.PwdTS,
	}

	expire := setting.GetInt(conf.LinkExpiration, 0)
	if expire == 0 {
		return NotExpiredWithUser(data, userInfo)
	} else {
		return WithDurationAndUser(data, userInfo, time.Duration(expire)*time.Hour)
	}
}

func WithDuration(data string, d time.Duration) string {
	once.Do(Instance)
	return instance.Sign(data, time.Now().Add(d).Unix())
}

func WithDurationAndUser(data string, user *sign.UserInfo, d time.Duration) string {
	once.Do(Instance)
	return instance.SignWithUser(data, user, time.Now().Add(d).Unix())
}

func NotExpired(data string) string {
	once.Do(Instance)
	return instance.Sign(data, 0)
}

func NotExpiredWithUser(data string, user *sign.UserInfo) string {
	once.Do(Instance)
	return instance.SignWithUser(data, user, 0)
}

func Verify(data string, sign string) error {
	once.Do(Instance)
	return instance.Verify(data, sign)
}

// VerifyAndExtractUser 验证签名并提取用户信息
func VerifyAndExtractUser(data string, signStr string) (*sign.UserInfo, error) {
	once.Do(Instance)
	return instance.VerifyAndExtractUser(data, signStr)
}

func Instance() {
	instance = sign.NewHMACSign([]byte(setting.GetStr(conf.Token)))
}
