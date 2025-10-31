package common

import (
	"context"
	"fmt"
	"net/http"
	"sql_demo/internal/utils"

	"github.com/gin-gonic/gin"
)

type JSONResponse struct {
	Code       int        `json:"status_code"`
	Message    string     `json:"message"`
	Data       any        `json:"data,omitempty"` // 数据可为空
	Pagination Pagniation `json:"pagination"`
}

type Option func(*JSONResponse)

// 新增分页器设置的选项
func WithPagination(p Pagniation) Option {
	return func(j *JSONResponse) {
		j.Pagination = p
	}
}

// 封装gin json成功响应
func SuccessResp(ctx *gin.Context, data any, msg string, opts ...Option) {
	jsonResp := &JSONResponse{
		Code:    RespSuccess,
		Message: msg,
		Data:    data,
	}
	// 选项式函数
	for _, opt := range opts {
		opt(jsonResp)
	}
	ctx.JSON(successCode, jsonResp)
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
	return fmt.Sprintf("[%s] %s", title, msg)
}

// 校验响应体
func ValidateRespBody(reqMethodName string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	ErrMsg := fmt.Sprintf("response status=%s, status_code=%d", resp.Status, resp.StatusCode)
	return utils.GenerateError(reqMethodName, ErrMsg)
}

// 检查上下文是否退出
func CheckCtx(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}
