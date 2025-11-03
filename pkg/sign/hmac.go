package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

type HMACSign struct {
	SecretKey []byte
}

func (s HMACSign) Sign(data string, expire int64) string {
	h := hmac.New(sha256.New, s.SecretKey)
	expireTimeStamp := strconv.FormatInt(expire, 10)
	_, err := io.WriteString(h, data+":"+expireTimeStamp)
	if err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(h.Sum(nil)) + ":" + expireTimeStamp
}

func (s HMACSign) SignWithUser(data string, user *UserInfo, expire int64) string {
	if user == nil {
		return s.Sign(data, expire)
	}

	// 将用户信息序列化为 JSON
	userJSON, err := json.Marshal(user)
	if err != nil {
		return ""
	}
	userB64 := base64.URLEncoding.EncodeToString(userJSON)

	// 生成 HMAC: hmac(data + userInfo + expire)
	h := hmac.New(sha256.New, s.SecretKey)
	expireTimeStamp := strconv.FormatInt(expire, 10)
	_, err = io.WriteString(h, data+":"+userB64+":"+expireTimeStamp)
	if err != nil {
		return ""
	}

	// 返回格式: signature:userInfo:expire
	return base64.URLEncoding.EncodeToString(h.Sum(nil)) + ":" + userB64 + ":" + expireTimeStamp
}

func (s HMACSign) Verify(data, sign string) error {
	signSlice := strings.Split(sign, ":")
	// check whether contains expire time
	if signSlice[len(signSlice)-1] == "" {
		return ErrExpireMissing
	}
	// check whether expire time is expired
	expires, err := strconv.ParseInt(signSlice[len(signSlice)-1], 10, 64)
	if err != nil {
		return ErrExpireInvalid
	}
	// if expire time is expired, return error
	if expires < time.Now().Unix() && expires != 0 {
		return ErrSignExpired
	}
	// verify sign
	if s.Sign(data, expires) != sign {
		return ErrSignInvalid
	}
	return nil
}

func (s HMACSign) VerifyAndExtractUser(data, sign string) (*UserInfo, error) {
	signSlice := strings.Split(sign, ":")

	// 检查格式: 应该是 signature:userInfo:expire (3 部分) 或 signature:expire (2 部分，旧格式)
	if len(signSlice) < 2 {
		return nil, ErrSignInvalid
	}

	// 如果是旧格式 (2 部分)，返回 nil user
	if len(signSlice) == 2 {
		err := s.Verify(data, sign)
		return nil, err
	}

	// 新格式: signature:userInfo:expire
	if len(signSlice) != 3 {
		return nil, ErrSignInvalid
	}

	userB64 := signSlice[1]
	expireStr := signSlice[2]

	// 检查过期时间
	if expireStr == "" {
		return nil, ErrExpireMissing
	}
	expires, err := strconv.ParseInt(expireStr, 10, 64)
	if err != nil {
		return nil, ErrExpireInvalid
	}
	if expires < time.Now().Unix() && expires != 0 {
		return nil, ErrSignExpired
	}

	// 解码用户信息
	userJSON, err := base64.URLEncoding.DecodeString(userB64)
	if err != nil {
		return nil, ErrUserInfoInvalid
	}

	var user UserInfo
	if err := json.Unmarshal(userJSON, &user); err != nil {
		return nil, ErrUserInfoInvalid
	}

	// 验证签名
	expectedSign := s.SignWithUser(data, &user, expires)
	if expectedSign != sign {
		return nil, ErrSignInvalid
	}

	return &user, nil
}

func NewHMACSign(secret []byte) Sign {
	return HMACSign{SecretKey: secret}
}
