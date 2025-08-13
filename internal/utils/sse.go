package utils

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
)

// 定义一个SSE消息内容对象
type SSEEvent struct {
	ID    int    `json:"event_id"` // 0=download ready; 1=frist connected; 2=failed; 4=close connected;
	Event string `json:"event"`
	Data  string `json:"data"`
}

// SSE发送Msg
func SSEMsgOnSend(ctx *gin.Context, event *SSEEvent) {
	sseMsgJSON, err := json.Marshal(event)
	if err != nil {
		ErrorPrint("JSONMarshalErr", err.Error())
		return
	}
	sendMsg := fmt.Sprintf("data: %s\n\n", sseMsgJSON)
	ctx.Writer.Write([]byte(sendMsg))
	ctx.Writer.Flush()
}
