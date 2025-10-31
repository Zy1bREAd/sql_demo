package utils

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 先用全局唯一secretKey
var secretKey string = "oceanwang-256-secret"

// 定义用户的声明,并且实现JWT接口
type UserClaim struct {
	OrignalClaims jwt.RegisteredClaims
	Email         string `json:"email"`
	UserID        string `json:"user_id"`
	UserKind      uint   `json:"user_kind"`
}

func (uc UserClaim) GetAudience() (jwt.ClaimStrings, error) {
	return uc.OrignalClaims.Audience, nil
}

func (uc UserClaim) GetExpirationTime() (*jwt.NumericDate, error) {
	return uc.OrignalClaims.ExpiresAt, nil
}

func (uc UserClaim) GetNotBefore() (*jwt.NumericDate, error) {
	return uc.OrignalClaims.NotBefore, nil
}

func (uc UserClaim) GetIssuedAt() (*jwt.NumericDate, error) {
	return uc.OrignalClaims.IssuedAt, nil
}

func (uc UserClaim) GetIssuer() (string, error) {
	return uc.OrignalClaims.Issuer, nil
}

func (uc UserClaim) GetSubject() (string, error) {
	return uc.OrignalClaims.Subject, nil
}

// func generateSecret() string {
// 	return GenerateSalt()
// }

func GenerateJWT(uid, name, email string, kind uint) (string, error) {
	userclaim := &UserClaim{
		OrignalClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(48 * time.Hour)), // default=3h
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    name,
		},
		Email:    email,
		UserID:   uid,
		UserKind: kind,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userclaim)
	tokenStr, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", GenerateError("GenerateJWTFailed", err.Error())
	}
	return tokenStr, nil
}

// 解析JWT
func ParseJWT(tokenStr string) (*UserClaim, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaim{}, func(t *jwt.Token) (interface{}, error) {
		// 判断jwt加密方法是否匹配
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, GenerateError("SignMethodNotMatch", "unexpected signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, GenerateError("ParseJWTError", err.Error())
	}
	// 断言判断获取声明
	if tokenClaim, ok := token.Claims.(*UserClaim); ok && token.Valid {
		return tokenClaim, nil
	}
	return nil, GenerateError("InvalidJWTClaim", "this is a invalid jwt claim")
}

// string转换uint的方法
func StrToUint(data string) uint {
	uintData, err := strconv.ParseUint(data, 10, 32)
	if err != nil {
		return 0
	}
	return uint(uintData)
}
