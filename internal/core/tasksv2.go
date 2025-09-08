package core

import (
	"encoding/json"
	"fmt"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

type SQLTask struct {
	ID        string
	Deadline  int // 单个SQL的超时时间（单位为秒）
	ParsedSQL SQLForParseV2
}

type QTaskGroupV2 struct {
	IsExport bool
	LongTime bool
	UserID   uint // 关联执行用户id
	Deadline int  //整个任务组的超时时间，默认: (用户SQL条数*用户定义的时间)+用户定义的时间
	GID      string
	TicketID string
	DML      string
	Env      string // 所执行环境
	DBName   string
	Service  string
	StmtRaw  string // 原生的SQL语句
	QTasks   []*SQLTask
}

// Ticket前置状态判断（符合状态流转约束）
func (tg *QTaskGroupV2) CheckTicketStats(targetStats []string) error {
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
func (tg *QTaskGroupV2) UpdateTicketStats(targetStats string) error {
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
func (tg *QTaskGroupV2) CreateAuditReocrd(eventName string) error {
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
