package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	api "sql_demo/api"
	glbapi "sql_demo/api/gitlab"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"sync"
)

var eventOnce sync.Once

// test
var TestCh chan struct{} = make(chan struct{}, 10)

func InitEventDrive(ctx context.Context, bufferSize int) {
	eventOnce.Do(func() {
		globalEventChannel := make(chan event.Event, bufferSize)
		// 生产者初始化
		ep := event.GetEventProducer()
		ep.Init(globalEventChannel)

		// 调度者初始化（事件路由注册）
		ed := event.GetEventDispatcher()
		ed.Init(3, globalEventChannel)
		// 调度者的Handler初始化
		registerMap := map[string]func() event.EventHandler{
			"sql_query":         NewQueryEventHandler,
			"save_result":       NewResultEventHandler,
			"clean_task":        NewCleanEventHandler,
			"export_result":     NewExportEventHandler,
			"file_housekeeping": NewHousekeepingEventHandler,
			"gitlab_webhook":    NewGitLabEventHandler,
			// "database_crud":     NewDBEventHandler,
		}
		for k, handler := range registerMap {
			err := ed.RegisterHandler(k, handler(), 5)
			if err != nil {
				panic(err)
			}
		}
	})
	// 启动调度者开始调度事件
	ed := event.GetEventDispatcher()
	go ed.Dispatch(ctx)
}

// 具体实现事件处理者
type QueryEventHandler struct {
}

func NewQueryEventHandler() event.EventHandler {
	return &QueryEventHandler{}
}

func (eh *QueryEventHandler) Name() string {
	return "查询事件处理者"
}

func (eh *QueryEventHandler) Work(ctx context.Context, e event.Event) error {
	// 判断哪种类型的QueryTask
	switch t := e.Payload.(type) {
	case *QueryTask:
		utils.DebugPrint("不再支持该类型SQL", t.ID)

	case *QTaskGroup: // 支持多SQL
		// Ticket前置状态判断（符合状态流转约束）
		var tk dbo.Ticket
		condTicket := dbo.Ticket{
			UID:      t.TicketID,
			AuthorID: int(t.UserID),
		}
		resultTicket, err := tk.Find(condTicket)
		if err != nil {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.GID, err.Error())
			rg := &dbo.SQLResultGroup{
				GID:      t.GID,
				ResGroup: make([]*dbo.SQLResult, 0),
				Errrr:    utils.GenerateError("TicketStatusErr", commentMsg),
			}
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: rg,
			})
			return nil
		}
		if resultTicket.Status != common.ApprovalPassedStatus && resultTicket.Status != common.ExcutePendingStatus {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.GID, "Ticket Status is invalid")
			rg := &dbo.SQLResultGroup{
				GID:      t.GID,
				ResGroup: make([]*dbo.SQLResult, 0),
				Errrr:    utils.GenerateError("TicketStatusErr", commentMsg),
			}
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: rg,
			})
			return nil
		}
		// 存储查询任务Map
		utils.DebugPrint("SQL查询Group事件消费", t.GID)
		QueryTaskMap.Set(t.GID, t, 300, 1)
		// 解析SQL语法V2
		stmtList, err := ParseV2(t.DBName, t.StmtRaw)
		if err != nil {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.GID, err.Error())
			rg := &dbo.SQLResultGroup{
				GID:      t.GID,
				ResGroup: make([]*dbo.SQLResult, 0),
				Errrr:    utils.GenerateError("SQLSyntaxError", commentMsg),
			}
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: rg,
			})
			return nil
		}
		// 构造任务组
		taskGroup := make([]*QueryTask, 0)
		for _, s := range stmtList {
			qTask := QueryTask{
				ID:       utils.GenerateUUIDKey(),
				SafeSQL:  s,
				Deadline: t.Deadline,
			}
			taskGroup = append(taskGroup, &qTask)
		}
		t.QTasks = taskGroup
		t.Deadline = len(taskGroup) * t.Deadline // 更新为正确的任务组超时时间
		// （更新）Ticket记录
		err = tk.UpdateStatus(condTicket, common.PendingStatus)
		if err != nil {
			return utils.GenerateError("TicketErr", err.Error())
		}
		t.ExcuteTask(ctx)

		jsonBytes, err := json.Marshal(taskGroup)
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		audit := dbo.AuditRecordV2{
			TaskID:   t.GID,
			UserID:   t.UserID,
			Payload:  string(jsonBytes),
			TaskType: common.QTaskGroupType,
		}
		// 日志审计插入v2
		err = audit.InsertOne("SQL_QUERY")
		if err != nil {
			return utils.GenerateError("AuditRecordErr", err.Error())
		}
	case *IssueQTask:
		var tk dbo.Ticket
		condTicket := dbo.Ticket{
			UID:      t.QTG.TicketID,
			AuthorID: int(t.QTG.UserID),
		}
		// Ticket前置状态判断
		resultTicket, err := tk.Find(condTicket)
		if err != nil {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.QTG.GID, err.Error())
			rg := &dbo.SQLResultGroup{
				GID:      t.QTG.GID,
				ResGroup: make([]*dbo.SQLResult, 0),
				Errrr:    utils.GenerateError("TicketStatusErr", commentMsg),
			}
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: rg,
			})
			return nil
		}
		if resultTicket.Status != common.ApprovalPassedStatus && resultTicket.Status != common.ExcutePendingStatus {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.QTG.GID, "Ticket Status is invalid")
			rg := &dbo.SQLResultGroup{
				GID:      t.QTG.GID,
				ResGroup: make([]*dbo.SQLResult, 0),
				Errrr:    utils.GenerateError("TicketStatusErr", commentMsg),
			}
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: rg,
			})
			return nil
		}
		// 存储查询任务Map
		utils.DebugPrint("Gitlab Issue SQL查询事件消费", t.QTG.GID)
		QueryTaskMap.Set(t.QTG.GID, t, 300, 1)
		// Issue评论情况更新并开始执行任务
		glab := glbapi.InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskId=%s is start work...", t.QTG.GID)
		glab.CommentCreate(t.IssProjectID, t.IssIID, updateMsg)
		// 解析SQL语法V2
		stmtList, err := ParseV2(t.QTG.DBName, t.QTG.StmtRaw)
		if err != nil {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.QTG.GID, err.Error())
			glab.CommentCreate(t.IssProjectID, t.IssIID, commentMsg)
			return err
		}
		// 构造任务组(缺少对deadline的默认设置)
		taskGroup := make([]*QueryTask, 0)
		var maxDeadline int
		for _, s := range stmtList {
			// 分别定义每个SQL语句的超时时间，SELECT和其他DML的不同超时时间
			var ddl int
			if t.QTG.LongTime {
				if s.Action == "select" {
					ddl = common.LongSelectDDL
				} else {
					ddl = common.LongOtherDDL
				}
			} else {
				if s.Action == "select" {
					ddl = common.SelectDDL
				} else {
					ddl = common.OtherDDL
				}
			}
			qTask := QueryTask{
				ID:       utils.GenerateUUIDKey(),
				SafeSQL:  s,
				Deadline: ddl,
			}
			taskGroup = append(taskGroup, &qTask)
			maxDeadline += ddl
		}
		t.QTG.QTasks = taskGroup
		t.QTG.Deadline = maxDeadline + 60
		// （更新）Ticket记录
		// err = tk.UpdateStatus(condTicket, common.PendingStatus)
		err = tk.Update(condTicket, dbo.Ticket{
			Status: common.PendingStatus,
			TaskID: t.QTG.GID,
		})
		if err != nil {
			return utils.GenerateError("TicketErr", err.Error())
		}
		// 执行查询任务组v2
		t.QTG.ExcuteTask(ctx)
		// 日志审计插入v2
		jsonBytes, err := json.Marshal(taskGroup)
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		audit := dbo.AuditRecordV2{
			TaskID:    t.QTG.GID,
			UserID:    t.QTG.UserID,
			Payload:   string(jsonBytes),
			ProjectID: t.IssProjectID,
			IssueID:   t.IssIID,
			TaskType:  common.IssueQTaskType,
		}
		// 日志审计插入v2
		err = audit.InsertOne("SQL_QUERY")
		if err != nil {
			return utils.GenerateError("AuditRecordErr", err.Error())
		}
	default:
		return utils.GenerateError("TaskTypeError", "event payload type is incrroect")
	}
	return nil
}

// 消费事件、处理结果
type ResultEventHandler struct {
}

func NewResultEventHandler() event.EventHandler {
	return &ResultEventHandler{}
}

func (eh *ResultEventHandler) Name() string {
	return "结果事件处理者"
}

func (eh *ResultEventHandler) Work(ctx context.Context, e event.Event) error {
	switch res := e.Payload.(type) {
	// 抽象成接口
	case *dbo.SQLResult:
		utils.DebugPrint("查询结果事件消费", res.ID)
		ResultMap.Set(res.ID, res, 300, 0)
	case *dbo.SQLResultGroup:
		utils.DebugPrint("查询结果组事件消费", res.GID)
		//! 后期核心处理结果集的代码逻辑块
		ResultMap.Set(res.GID, res, 300, 0)
		TestCh <- struct{}{}
		// 判断是否为GItLab Issue的任务
		val, exist := QueryTaskMap.Get(res.GID)
		if !exist {
			return nil
		}
		// 判断是否gitlab issue任务逻辑
		v, ok := val.(*IssueQTask)
		if !ok {
			return nil
		}
		// （更新）Ticket记录
		var tk dbo.Ticket
		// Issue评论情况更新
		glab := glbapi.InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskGId=%s is completed", res.GID)
		glab.CommentCreate(v.IssProjectID, v.IssIID, updateMsg)
		for _, result := range res.ResGroup {
			if result.Errrrr != nil {
				errMsg := fmt.Sprintf("- TaskGId=%s\n- IID=%s\n- TaskError=%s", res.GID, result.ID, result.ErrMsg)
				err := glab.CommentCreate(v.IssProjectID, v.IssIID, errMsg)
				if err != nil {
					utils.DebugPrint("CommentError", "query task result comment is failed"+err.Error())
				}
				// Ticket状态：失败
				err = tk.UpdateStatus(dbo.Ticket{
					UID:      v.QTG.TicketID,
					AuthorID: int(v.QTG.UserID),
				}, common.FailedStatus)
				if err != nil {
					return utils.GenerateError("TicketErr", err.Error())
				}
				// break
				return nil
			}
		}
		// Ticket状态：成功
		err := tk.UpdateStatus(dbo.Ticket{
			UID:      v.QTG.TicketID,
			AuthorID: int(v.QTG.UserID),
		}, common.CompletedStatus)
		if err != nil {
			return utils.GenerateError("TicketErr", err.Error())
		}
		// 存储结果、输出结果临时链接
		uuKey, tempURL := glbapi.NewHashTempLink()
		err = dbo.SaveTempResult(uuKey, res.GID, 300, v.QTG.IsExport)
		if err != nil {
			utils.DebugPrint("SaveTempResultError", "db save result link is failed "+err.Error())
		}
		glab.CommentCreate(v.IssProjectID, v.IssIID, tempURL)
		// 自动关闭issue（表示完成）
		// err = glab.IssueClose(v.IssProjectID, v.IssIID)
		// if err != nil {
		// 	utils.DebugPrint("GitLabAPIError", err.Error())
		// }
		// 完成通知
		iss, err := glab.IssueView(v.IssProjectID, v.IssIID)
		if err != nil {
			utils.DebugPrint("GitLabAPIError", err.Error())
		}
		rob := api.NewRobotNotice(&api.InformTemplate{
			UserName: v.IssAuthorName,
			Action:   "Completed",
			Link:     iss.WebURL,
		})
		err = rob.InformRobot()
		if err != nil {
			utils.DebugPrint("InformError", err.Error())
		}
	default:
		typeName := reflect.TypeOf(e.Payload)
		log.Println("没有匹配到的结果集类型", typeName)
		TestCh <- struct{}{}
	}
	return nil
}

type CleanEventHandler struct {
	cleanTypeMap     map[int]*CachesMap
	cleanTypeInfoMap map[int]string
}

func NewCleanEventHandler() event.EventHandler {

	return &CleanEventHandler{
		cleanTypeMap: map[int]*CachesMap{
			0: ResultMap,
			1: QueryTaskMap,
			2: SessionMap,
			3: ExportWorkMap,
		},
		cleanTypeInfoMap: map[int]string{
			0: "ResultMap",
			1: "QueryTaskMap",
			2: "SessionMap",
			3: "ExportWorkMap",
		},
	}
}

func (eh *CleanEventHandler) Name() string {
	return "清理事件处理者"
}

func (eh *CleanEventHandler) Work(ctx context.Context, e event.Event) error {
	body, ok := e.Payload.(cleanTask)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	utils.DebugPrint("清理结果事件消费", body.ID)
	//! 后期核心处理结果集的代码逻辑块
	mapOperator := eh.cleanTypeMap[body.Type]
	mapOperator.Del(body.ID)
	log.Printf("type=%v taskID=%s Cleaned Up", eh.cleanTypeInfoMap[body.Type], body.ID)
	return nil
}

// 结果导出者
type ExportEventHandler struct {
}

func NewExportEventHandler() event.EventHandler {

	return &ExportEventHandler{}
}

func (eh *ExportEventHandler) Name() string {
	return "导出结果事件处理者"
}

func (eh *ExportEventHandler) Work(ctx context.Context, e event.Event) error {
	t, ok := e.Payload.(*ExportTask)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	//! 后期核心处理结果集的代码逻辑块
	utils.DebugPrint("ExportTask", "export task "+t.GID+" is starting...")
	err := t.Export(ctx)
	if err != nil {
		// 添加错误信息
		t.Result.Error = err
		t.Result.FilePath += "_failed"
		t.Result.Done <- struct{}{}
		utils.DebugPrint("ExportTask", "export task "+t.GID+" is failed,error: "+err.Error())
		return nil
	}
	utils.DebugPrint("ExportTask", "export task "+t.GID+" is completed")
	return nil
}

// 文件清理者
type HousekeepingEventHandler struct {
}

func NewHousekeepingEventHandler() event.EventHandler {

	return &HousekeepingEventHandler{}
}

func (eh *HousekeepingEventHandler) Name() string {
	return "文件清理事件处理者"
}

func (eh *HousekeepingEventHandler) Work(ctx context.Context, e event.Event) error {
	body, ok := e.Payload.(*ExportTask)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	utils.DebugPrint("文件清理事件消费", body.GID)
	//! 后期核心处理结果集的代码逻辑块
	body.Clean(ctx)
	return nil
}

type GitLabEventHandler struct {
}

func NewGitLabEventHandler() event.EventHandler {

	return &GitLabEventHandler{}
}

func (eg *GitLabEventHandler) Name() string {
	return "GitLab事件处理者"
}

// 区分gitlab事件
func (eg *GitLabEventHandler) Work(ctx context.Context, e event.Event) error {
	body, ok := e.Payload.(*glbapi.GitLabWebhook)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	// 审批or驳回的逻辑
	switch body.Webhook {
	case glbapi.CommentHandle:
		payload, ok := body.Payload.(*glbapi.CommentPayload)
		if !ok {
			return utils.GenerateError("PayloadErr", "payload is invalid")
		}
		gid := utils.GenerateUUIDKey() // UUID
		switch payload.Action {
		case glbapi.CommentApprovalPassed:
			sqlt := payload.IssuePayload.Desc //  获取SQLIssueTemplate
			issue := payload.IssuePayload.Issue
			// 获取USer真实ID
			user := dbo.User{
				GitLabIdentity: payload.IssuePayload.Issue.AuthorID,
			}
			userId := user.GetGitLabUserId()
			ep := event.GetEventProducer()

			// （更新）Ticket记录
			var tk dbo.Ticket
			err := tk.UpdateStatus(dbo.Ticket{
				ProjectID: int(issue.ProjectID),
				IssueID:   int(issue.IID),
			}, common.ApprovalPassedStatus)
			if err != nil {
				return err
			}
			ticketBody, err := tk.Find(tk)
			if err != nil {
				return err
			}
			// 审批通过进入查询阶段
			ep.Produce(event.Event{
				Type: "sql_query",
				Payload: &IssueQTask{
					QTG: &QTaskGroup{
						GID:      gid,
						TicketID: ticketBody.UID,
						DML:      sqlt.Action,
						UserID:   userId,
						DBName:   sqlt.DBName,
						Env:      sqlt.Env,
						Service:  sqlt.Service,
						StmtRaw:  sqlt.Statement,
						IsExport: sqlt.IsExport,
						// Deadline: 90,
						LongTime: sqlt.LongTime,
					},
					IssProjectID:  issue.ProjectID,
					IssIID:        issue.IID,
					IssAuthorID:   issue.AuthorID,
					IssAuthorName: issue.Author.Name,
				},
			})
			utils.DebugPrint("TaskEnqueue", fmt.Sprintf("task id=%s is enqueue", gid))
		case glbapi.CommentApprovalReject:
			// （更新）Ticket记录
			var tk dbo.Ticket
			err := tk.UpdateStatus(dbo.Ticket{
				ProjectID: int(payload.IssuePayload.Issue.ProjectID),
				IssueID:   int(payload.IssuePayload.Issue.IID),
			}, common.ApprovalRejectStatus)
			if err != nil {
				return err
			}
		default:
			return utils.GenerateError("CommentActionErr", "comment action is unknow type")
		}
	case glbapi.IssueHandle:
		payload, ok := body.Payload.(*glbapi.IssuePayload)
		if !ok {
			return utils.GenerateError("PayloadErr", "payload is invalid")
		}
		// 获取用户真实ID
		user := dbo.User{
			GitLabIdentity: payload.Issue.AuthorID,
		}
		userId := user.GetGitLabUserId()
		// （创建）Ticket记录
		ticket := dbo.Ticket{
			UID:       fmt.Sprintf("ticket_%d%d%d", payload.Issue.ProjectID, payload.Issue.IID, userId), // ProjectID + IssueID + AuthorID
			Status:    common.CreatedStatus,
			AuthorID:  int(userId),
			ProjectID: int(payload.Issue.ProjectID),
			IssueID:   int(payload.Issue.IID),
			Link:      fmt.Sprintf("http://159.75.119.146:28660/infra/demo_1/-/issues/%d", int(payload.Issue.IID)),
		}
		err := ticket.FristOrCreate()
		if err != nil {
			glab := glbapi.InitGitLabAPI()
			glab.CommentCreate(uint(payload.Issue.ProjectID), uint(payload.Issue.IID), "Create Ticket Error::"+err.Error())
			return err
		}
	}

	return nil
}
