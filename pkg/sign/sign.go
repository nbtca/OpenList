package sign

import "errors"

type UserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	PwdTS    int64  `json:"pwd_ts"`
}

type Sign interface {
	Sign(data string, expire int64) string
	Verify(data, sign string) error
	SignWithUser(data string, user *UserInfo, expire int64) string
	VerifyAndExtractUser(data, sign string) (*UserInfo, error)
}

var (
	ErrSignExpired     = errors.New("sign expired")
	ErrSignInvalid     = errors.New("sign invalid")
	ErrExpireInvalid   = errors.New("expire invalid")
	ErrExpireMissing   = errors.New("expire missing")
	ErrUserInfoInvalid = errors.New("user info invalid")
)
