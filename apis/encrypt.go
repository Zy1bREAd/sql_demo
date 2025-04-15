package apis

import (
	"crypto/md5"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// uuid v4
func GenerateUUIDKey() string {
	return uuid.New().String()
}

// 通过uuid生成salt
func GenerateSalt() string {
	originalSalt := GenerateUUIDKey()
	saltVal := strings.ReplaceAll(originalSalt, "-", "")
	return saltVal
}

// 使用salt进行MD5加密
func EncryptWithSaltMd5(salt, original string) string {
	h := md5.New()
	_, _ = h.Write([]byte(salt + original))
	encryptVal := hex.EncodeToString(h.Sum(nil))
	// 最终密码格式为：盐值(32位)$加密后的密码(32位)
	return salt + "$" + encryptVal
}

// 验证加salt的string
func ValidateValueWithMd5(inputVal, encryptVal string) bool {
	salt := strings.Split(encryptVal, "$")[0]
	encryptInputVal := EncryptWithSaltMd5(salt, inputVal)
	return encryptInputVal == encryptVal
}
