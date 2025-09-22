package core

import (
	"context"
	"fmt"
	"sql_demo/internal/conf"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"time"
)

type QueryTaskV2 struct {
	ID       string
	Deadline int // 单个SQL的超时时间（单位为秒）
	SafeSQL  SQLForParseV2
}

type SQLTask struct {
	ID        string // IID - 任务ID
	Deadline  int    // 单个SQL的超时时间（单位为秒）
	ParsedSQL SQLForParseV2
}

// 检查事件payload
type CheckEvent interface {
	UpdateTicketStats(targetStats string, exceptStats ...string) error
}
type FristCheckEvent struct {
	SourceRef string
	Source    string
	TicketID  int64
	UserID    uint
}

type DoubleCheckEvent struct {
	FristCheckEvent
	FristCheck *PreCheckResultGroup
}

// 执行or查询任务
type QTaskGroupV2 struct {
	IsAiAnalysis   bool
	IsSoarAnalysis bool
	IsExport       bool
	IsLongTime     bool
	UserID         uint // 关联执行用户id
	Deadline       int  //整个任务组的超时时间，默认: (用户SQL条数*用户定义的时间)+用户定义的时间
	TicketID       int64
	GID            string // 任务组ID（使用TicketID可唯一追踪一个任务组）
	DML            string
	Env            string // 所执行环境
	DBName         string
	Service        string
	StmtRaw        string // 原生的SQL语句
	QTasks         []*SQLTask
}

// 封装QueryTask 结合GitLab Issue
type IssueQTaskV2 struct {
	QTG           *QTaskGroupV2
	IssProjectID  uint
	IssIID        uint
	IssAuthorID   uint
	IssAuthorName string
	// IssDesc       *gapi.SQLIssueTemplate
}

// Ticket前置状态判断（符合状态流转约束）
func (ce *FristCheckEvent) CheckTicketStats(targetStats []string) error {
	var tk dbo.Ticket
	condTicket := dbo.Ticket{
		UID:      ce.TicketID,
		AuthorID: ce.UserID,
	}
	resultTicket, err := tk.FindOne(condTicket)
	if err != nil {
		return err
	}
	for _, stats := range targetStats {
		if resultTicket.Status == stats {
			continue
		}
		commentMsg := fmt.Sprintf("TraceID=%d\n- TaskError=%s", ce.TicketID, "Ticket Status is not match")
		return utils.GenerateError("TicketStatusErr", commentMsg)
	}
	return nil
}

// 更新Ticket状态信息，并按照指定前置状态进行判断
func (ce *FristCheckEvent) UpdateTicketStats(targetStats string, exceptStats ...string) error {
	// 更新Ticket信息
	var tk dbo.Ticket
	condTicket := dbo.Ticket{
		UID:      ce.TicketID,
		AuthorID: ce.UserID,
	}
	return tk.ValidateAndUpdateStatus(condTicket, targetStats, exceptStats...)
}

// 更新Ticket状态信息，并按照指定前置状态进行判断
func (ce *DoubleCheckEvent) UpdateTicketStats(targetStats string, exceptStats ...string) error {
	// 更新Ticket信息
	var tk dbo.Ticket
	condTicket := dbo.Ticket{
		UID:      ce.TicketID,
		AuthorID: ce.UserID,
	}
	return tk.ValidateAndUpdateStatus(condTicket, targetStats, exceptStats...)
}

// 任务组：创建审计日日志
// func (tg *QTaskGroupV2) CreateAuditReocrd(eventName string) error {
// 	jsonBytes, err := json.Marshal(tg.QTasks)
// 	if err != nil {
// 		utils.ErrorPrint("AuditRecordV2", err.Error())
// 	}
// 	audit := dbo.AuditRecordV2{
// 		TicketID: tg.TicketID,
// 		TaskID:   tg.GID,
// 		UserID:   tg.UserID,
// 		Payload:  string(jsonBytes),
// 		TaskKind: common.IssueQTaskType,
// 	}
// 	// 日志审计插入v2
// 	err = audit.InsertOne(eventName)
// 	return err
// }

// 多SQL执行(可Query可Excute), 遇到错误立即退出后续执行
func (qtg *QTaskGroupV2) ExcuteTask(ctx context.Context) {
	utils.DebugPrint("TaskDetails", fmt.Sprintf("Task GID=%s is working...", qtg.GID))
	//! 执行任务函数只当只关心任务处理逻辑本身

	ep := event.GetEventProducer()
	rg := &SQLResultGroupV2{
		GID:  qtg.TicketID, // 统一使用TicketID
		Data: make([]*dbo.SQLResult, 0),
	}

	for _, task := range qtg.QTasks {
		// 子任务超时控制
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(task.Deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
		defer cancel()
		utils.DebugPrint("TaskDetails", fmt.Sprintf("Task IID=%s is working...", task.ID))
		var result dbo.SQLResult = dbo.SQLResult{
			ID:   task.ID,
			Stmt: task.ParsedSQL.SafeStmt,
		}
		// 获取对应数据库实例进行SQL查询
		op, err := dbo.HaveDBIst(qtg.Env, qtg.DBName, qtg.Service)
		if err != nil {
			result.Errrrr = err
			result.ErrMsg = result.Errrrr.Error()
			rg.Data = append(rg.Data, &result)
			break
		}
		// 执行前健康检查DB
		err = op.HealthCheck(timeoutCtx)
		if err != nil {
			result.Errrrr = utils.GenerateError("HealthCheckFailed", err.Error())
			result.ErrMsg = result.Errrrr.Error()
			rg.Data = append(rg.Data, &result)
			break
		}
		// 主要分查询和执行，核心通过解析SQL语句的类型来实现对应的逻辑
		if task.ParsedSQL.Action == "select" {
			result = op.Query(timeoutCtx, task.ParsedSQL.SafeStmt, task.ID, conf.DataMaskHandle)
		} else {
			result = op.Excute(timeoutCtx, task.ParsedSQL.SafeStmt, task.ID)
		}

		rg.Data = append(rg.Data, &result)
		// 如果该条SQL遇到ERROR立即中止后续执行
		if result.Errrrr != nil {
			utils.ErrorPrint("TaskDetails", fmt.Sprintf("Task IID=%s is failed", task.ID))
			break
		}
		utils.DebugPrint("TaskDetails", fmt.Sprintf("Task IID=%s is completed", task.ID))
	}
	utils.DebugPrint("TaskDetails", fmt.Sprintf("Task GID=%s is completed", qtg.GID))
	ep.Produce(event.Event{
		Type:    "save_result",
		Payload: rg,
	})
}
