package apis

import (
	"crypto/md5"

	"github.com/google/uuid"
)

// uuid v4
func GenerateUUIDKey() string {
	return uuid.New().String()
}

// md5 encrypt
func EncryptWithMd5(original string) string {
	h := md5.New()
	return string(h.Sum([]byte(original)))
}
