package core

import (
	"encoding/json"
	"fmt"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

// Ticket前置状态判断（符合状态流转约束）
func (tg *QTaskGroup) CheckTicketStats(targetStats []string) error {
	var tk dbo.Ticket
	condTicket := dbo.Ticket{
		UID:      tg.TicketID,
		AuthorID: int(tg.UserID),
	}
	resultTicket, err := tk.Find(condTicket)
	if err != nil {
		return err
	}
	for _, stats := range targetStats {
		if resultTicket.Status == stats {
			continue
		}
		commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", tg.GID, "Ticket Status is not match")
		return utils.GenerateError("TicketStatusErr", commentMsg)
	}
	return nil
}

// 更新Ticket状态信息
func (tg *QTaskGroup) UpdateTicketStats(targetStats string) error {
	// 更新Ticket信息
	var tk dbo.Ticket
	condTicket := dbo.Ticket{
		UID:      tg.TicketID,
		AuthorID: int(tg.UserID),
	}
	err := tk.UpdateStatus(condTicket, targetStats)
	return err
}

// 更新Ticket状态信息
func (tg *QTaskGroup) CreateAuditReocrd(eventName string) error {
	jsonBytes, err := json.Marshal(tg.QTasks)
	if err != nil {
		utils.ErrorPrint("AuditRecordV2", err.Error())
	}
	audit := dbo.AuditRecordV2{
		TaskID:   tg.GID,
		UserID:   tg.UserID,
		Payload:  string(jsonBytes),
		TaskType: common.QTaskGroupType,
	}
	// 日志审计插入v2
	err = audit.InsertOne(eventName)
	return err
}
