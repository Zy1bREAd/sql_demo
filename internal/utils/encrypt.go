package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/google/uuid"
)

var snowNode *snowflake.Node

// uuid v4
func GenerateUUIDKey() string {
	return uuid.New().String()
}

// 生成雪花ID
func GenerateSnowKey() int64 {
	if snowNode == nil {
		node, err := snowflake.NewNode(1)
		if err != nil {
			panic("New SnowFlake Node Is Error" + err.Error())
		}
		snowNode = node
	}
	id := snowNode.Generate()
	return id.Int64()
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

func Str2TimeObj(t string) time.Time {
	newT, err := time.Parse(time.DateTime, t)
	if err != nil {
		DebugPrint("FormatTimeError", err.Error())
		// 出现则返回1970的时间段！
		return time.Unix(0, 0)
	}
	return newT
}

// ! 对称加密算法AES-256
func EncryptAES256(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// 填充明文（AES 要求明文长度为块大小的整数倍）
	blockSize := block.BlockSize()
	plaintext = pkcs7Pad(plaintext, blockSize)
	// 生成随机 IV（初始化向量）
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 加密
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// 合并 IV 和密文（IV 需随密文存储，解密时使用）
	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
}

// AES 解密（密钥需与加密时一致）
func DecryptAES256(ciphertextBase64, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertextBase64))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 分离 IV 和密文
	blockSize := block.BlockSize()
	if len(ciphertext) < blockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	// 解密
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// 去除填充
	plaintext, err := pkcs7Unpad(ciphertext, blockSize)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// PKCS7 填充（AES 要求）
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(data, padding...)
}

// PKCS7 去填充
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data)%blockSize != 0 {
		return nil, errors.New("data is not block-aligned")
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}

func StudyFn() {
	once := sync.OnceValue(func() int {
		sum := 0
		for i := 0; i < 1000; i++ {
			sum += i
		}
		return sum
	})
	done := make(chan bool, 10)
	// 开启多个goroutine共同调用once
	for i := 0; i < 50; i++ {
		go func() {
			val := once()
			if val != 499500 {
				fmt.Println("got got want want")
				done <- false
				return
			}
			fmt.Println("i=", i)
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		msg, ok := <-done
		if !ok {
			fmt.Println("closed channel")
			return
		}
		fmt.Println(msg)
	}
}
