package common

import (
	"fmt"
	"net/http"
	"sql_demo/internal/utils"

	"github.com/gin-gonic/gin"
)

// ! 封装响应数据
const (
	successCode = 200
	errorCode   = 500
)

// ! 封装App业务性的响应状态码
// 普通成功的都为个位数，错误通常都是两位数。
const (
	RespSuccess = 100
	RespFailed  = 11 // 未知错误的默认失败

	RecordNotExist = 44
	RecordNotFound = 45
)

type JSONResponse struct {
	Code    int    `json:"status_code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"` // 数据可为空
}

// 封装gin json成功响应
func SuccessResp(ctx *gin.Context, data any, msg string) {
	ctx.JSON(successCode, JSONResponse{
		Code:    RespSuccess,
		Message: msg,
		Data:    data,
	})
}

// 封装gin json错误响应
func ErrorResp(ctx *gin.Context, msg string) {
	ctx.JSON(errorCode, JSONResponse{
		Code:    RespFailed,
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

// 校验响应体
func ValidateRespBody(reqMethodName string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	ErrMsg := fmt.Sprintf("response status=%s, status_code=%d", resp.Status, resp.StatusCode)
	return utils.GenerateError(reqMethodName, ErrMsg)
}
