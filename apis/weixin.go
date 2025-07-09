package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type RobotNotice struct {
	MsgType  string      `json:"msgtype"`
	Markdown MarkdownMsg `json:"markdown"`
}

type MarkdownMsg struct {
	Content string `json:"content"`
}

// 考虑不同场景下的机器人通知模板, 包装结构体来传入通知消息的参数
type TicketInformBody struct {
	UserName      string
	TicketType    string
	TicketDesc    string
	TicketLink    string
	TicketDueDate string
}

func (body *TicketInformBody) Fill() string {
	return fmt.Sprintf("【%s】\n>User: %s\n>Due Date: %s\n>Description: %s\n>Link: %s", body.TicketType, body.UserName, body.TicketDueDate, body.TicketDesc, body.TicketLink)
}

type RejectInformBody struct {
	UserName   string
	TicketLink string
	TicketType string
	Reason     string
	Approver   string // 审批人
}

func (body *RejectInformBody) Fill() string {
	return fmt.Sprintf("【%s】\n>User: %s\n>Reason: %s\n>Approver: %s\n>Link: %s", body.TicketType, body.UserName, body.Reason, body.Approver, body.TicketLink)
}

func InformRobot(content string) error {
	informURL := GetAppConfig().WeixinEnv.InformWebhook
	if informURL == "" {
		DebugPrint("IsURLNull", "inform url is null")
		return nil
	}
	// 序列化数据
	fmt.Println(informURL, content)
	jsonData, err := json.Marshal(content)
	if err != nil {
		return GenerateError("JSONMarshal", err.Error())
	}

	req, err := http.NewRequest("POST", informURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return GenerateError("NewRequest", err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	client := http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return GenerateError("RequestError", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		DebugPrint("RequestError", resp.Body)
		return GenerateError("RequestError", resp.Status)
	}

	return nil
}
