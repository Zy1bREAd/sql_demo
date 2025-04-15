package apis

import "github.com/gin-gonic/gin"

//! 封装响应数据
const (
	successCode = 200
	errorCode   = 500
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
