package apis

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// ! 封装响应数据
const (
	successCode = 200
	errorCode   = 500
)

// ! 封装App业务性的响应状态码
const (
	APP_SUCCESS = 0
	APP_FAILED  = 1
)

type JSONResponse struct {
	Code    int    `json:"status_code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"` // 数据可为空
}

// 封装gin json成功响应
func SuccessResp(ctx *gin.Context, data any, msg string) {
	ctx.JSON(successCode, JSONResponse{
		Code:    successCode,
		Message: msg,
		Data:    data,
	})
}

// 封装gin json错误响应
func ErrorResp(ctx *gin.Context, msg string) {
	ctx.JSON(errorCode, JSONResponse{
		Code:    errorCode,
		Message: msg,
	})
}

func DefaultResp(ctx *gin.Context, code int, data any, msg string) {
	ctx.JSON(successCode, JSONResponse{
		Code:    code,
		Data:    data,
		Message: msg,
	})
}

func NotAuthResp(ctx *gin.Context, msg string) {
	ctx.JSON(401, JSONResponse{
		Message: msg,
	})
}

func FormatPrint(title, msg string) string {
	return fmt.Sprintf("[%s] - %s", title, msg)
}
