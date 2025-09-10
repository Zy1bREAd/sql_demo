package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"slices"
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
			"sql_check": NewCheckEventHandler,
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
		resultTicket, err := tk.FindOne(condTicket)
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
		if resultTicket.Status != common.OnlinePassedStatus {
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

		// 构造任务组
		// taskGroup := make([]*QueryTask, 0)
		// for _, s := range stmtList {
		// 	qTask := QueryTask{
		// 		ID:       utils.GenerateUUIDKey(),
		// 		SafeSQL:  s,
		// 		Deadline: t.Deadline,
		// 	}
		// 	taskGroup = append(taskGroup, &qTask)
		// }
		// t.QTasks = taskGroup
		// t.Deadline = len(taskGroup) * t.Deadline // 更新为正确的任务组超时时间
		// （更新）Ticket记录
		err = tk.ValidateStatus(condTicket, []string{common.OnlinePassedStatus}...)
		if err != nil {
			return utils.GenerateError("TicketErr", err.Error())
		}
		t.ExcuteTask(ctx)

		// jsonBytes, err := json.Marshal(taskGroup)
		// if err != nil {
		// 	utils.ErrorPrint("AuditRecordV2", err.Error())
		// }
		audit := dbo.AuditRecordV2{
			TaskID: t.GID,
			UserID: t.UserID,
			// Payload:  string(jsonBytes),
			TaskType: common.QTaskGroupType,
		}
		// 日志审计插入v2
		err = audit.InsertOne("SQL_QUERY")
		if err != nil {
			return utils.GenerateError("AuditRecordErr", err.Error())
		}
	case *IssueQTaskV2:

		// Ticket前置状态判断
		var tk dbo.Ticket
		condTicket := dbo.Ticket{
			UID:      t.QTG.TicketID,
			AuthorID: int(t.QTG.UserID),
		}
		err := tk.ValidateStatus(condTicket, []string{common.OnlinePassedStatus}...)
		if err != nil {
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
		// 获取预检结果，进行二次校验
		val, exist := CheckTaskMap.Get(t.QTG.GID)
		if !exist {
			commentMsg := fmt.Sprintf("- TaskGId=%s\n- TaskError=%s", t.QTG.GID, "Pre-Check result is not exist")
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
		precheckRes, ok := val.(*PreCheckResultGroup)
		if !ok {
			panic("CheckTaskResult Type is invalid")
		}

		// 存储查询任务Map
		utils.DebugPrint("Gitlab Issue SQL查询事件消费", t.QTG.GID)
		QueryTaskMap.Set(t.QTG.GID, t, 300, 1)
		// Issue评论情况更新并开始执行任务
		glab := glbapi.InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskId=%s is start work...", t.QTG.GID)
		glab.CommentCreate(t.IssProjectID, t.IssIID, updateMsg)

		// 构造任务组(缺少对deadline的默认设置)
		taskGroup := make([]*SQLTask, 0)
		var maxDeadline int
		for _, s := range precheckRes.Data.ParsedSQL {
			// 分别定义每个SQL语句的超时时间，SELECT和其他DML的不同超时时间
			var ddl int
			if t.QTG.IsLongTime {
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
			qTask := SQLTask{
				ID:        utils.GenerateUUIDKey(),
				ParsedSQL: s,
				Deadline:  ddl,
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
	case *PreCheckResultGroup:
		utils.DebugPrint("这是预检结果事件", "pre-check"+res.GID)
		//! 存储预检任务信息
		CheckTaskMap.Set(res.GID, res, common.DefaultCacheMapDDL, common.CheckTaskMapCleanFlag)

		// GitLab Issue通知详情
		val, exist := GitLabIssueMap.Get(res.GID)
		if !exist {
			return nil
		}
		// 判断是否为GItLab Issue的任务缓存
		v, ok := val.(*glbapi.IssueCache)
		if !ok {
			utils.ErrorPrint("AssertError", "Unknown Type")
			return nil
		}
		// Issue评论情况更新
		glab := glbapi.InitGitLabAPI()
		updateMsg := "Update Message"
		if res.Errrr != nil {
			updateMsg = fmt.Sprintf("- TaskGId=%s \nPre-Check Task is Failed\n- %s", res.GID, res.Errrr.Error())
		} else {
			updateMsg = fmt.Sprintf("- TaskGId=%s \nPre-Check Task is Susscess\n", res.GID)
		}
		err := glab.CommentCreate(v.ProjectID, v.Issue.IID, updateMsg)
		if err != nil {
			utils.ErrorPrint("GitlabCommentErr", err.Error())
		}

	case *SQLResultGroupV2:
		utils.DebugPrint("查询结果组v2事件消费", res.GID)
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
		updateMsg := fmt.Sprintf("- TaskGId=%s is completed", res.GID)
		glab.CommentCreate(v.IssProjectID, v.IssIID, updateMsg)
		for _, result := range res.Data {
			if result.Errrrr != nil {
				errMsg := fmt.Sprintf("- TaskGId=%s\n- IID=%s\n- TaskError=%s", res.GID, result.ID, result.ErrMsg)
				err := glab.CommentCreate(v.IssProjectID, v.IssIID, errMsg)
				if err != nil {
					utils.DebugPrint("CommentError", "query task result comment is failed"+err.Error())
				}
				// Ticket状态：失败
				// targetStats := []string{common.}
				err = tk.ValidateAndUpdateStatus(dbo.Ticket{
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
		err := tk.ValidateAndUpdateStatus(dbo.Ticket{
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
		err = glab.IssueClose(v.IssProjectID, v.IssIID)
		if err != nil {
			utils.DebugPrint("GitLabAPIError", err.Error())
		}
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
			4: CheckTaskMap,
		},
		cleanTypeInfoMap: map[int]string{
			0: "ResultMap",
			1: "QueryTaskMap",
			2: "SessionMap",
			3: "ExportWorkMap",
			4: "CheckTaskMap",
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
	glab := glbapi.InitGitLabAPI()
	// 审批or驳回的逻辑
	switch body.Webhook {
	case glbapi.CommentHandle:
		payload, ok := body.Payload.(*glbapi.CommentPayload)
		if !ok {
			return utils.GenerateError("PayloadErr", "payload is invalid")
		}
		switch payload.Action {
		case glbapi.CommentOnlineExcute: //! 执行上线
			// 通过Issue信息获取GID
			var tk dbo.Ticket
			dbConn := dbo.HaveSelfDB().GetConn()
			res := dbConn.Where(&dbo.Ticket{
				SourceRef: fmt.Sprintf("gitlab:%d:%d:%d", payload.IssuePayload.Issue.AuthorID, payload.IssuePayload.Issue.ProjectID, payload.IssuePayload.Issue.IID),
			}).Last(&tk)
			if res.Error != nil {
				commentMsg := fmt.Sprintf("[TicketErr] **%s**", res.Error.Error())
				err := glab.CommentCreate(uint(payload.IssuePayload.Issue.ProjectID), uint(payload.IssuePayload.Issue.IID), commentMsg)
				if err != nil {
					utils.ErrorPrint("CommentFailed", err.Error())
				}
			}

			sqlt := payload.IssuePayload.Desc //  获取SQLIssueTemplate
			issue := payload.IssuePayload.Issue
			// 获取USer真实ID
			user := dbo.User{
				GitLabIdentity: payload.IssuePayload.Issue.AuthorID,
			}
			userId := user.GetGitLabUserId()
			ep := event.GetEventProducer()

			//! 上线前检查是否有修改痕迹
			targetStats := []string{
				common.ApprovalPassedStatus,
			}
			// （更新）Ticket记录
			err := tk.ValidateAndUpdateStatus(dbo.Ticket{
				ProjectID: int(issue.ProjectID),
				IssueID:   int(issue.IID),
			}, common.OnlinePassedStatus, targetStats...)
			if err != nil {
				commentMsg := fmt.Sprintf("[UpdateTicketErr] **%s**", err.Error())
				err := glab.CommentCreate(uint(payload.IssuePayload.Issue.ProjectID), uint(payload.IssuePayload.Issue.IID), commentMsg)
				if err != nil {
					utils.ErrorPrint("CommentFailed", err.Error())
				}
			}

			// 发起sql_query的事件，准备执行SQL
			ep.Produce(event.Event{
				Type: "sql_query",
				Payload: &IssueQTask{
					QTG: &QTaskGroup{
						GID:      tk.SourceRef,
						TicketID: tk.UID,
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
		case glbapi.CommentApprovalPassed:
			issue := payload.IssuePayload.Issue

			// 校验状态并更新Ticket
			targetStats := []string{
				common.PreCheckSuccessStatus,
			}
			var tk dbo.Ticket
			err := tk.ValidateAndUpdateStatus(dbo.Ticket{
				ProjectID: int(issue.ProjectID),
				IssueID:   int(issue.IID),
			}, common.OnlinePendingStatus, targetStats...)
			if err != nil {
				commentMsg := fmt.Sprintf("[UpdateTicketErr] **%s**", err.Error())
				err := glab.CommentCreate(uint(payload.IssuePayload.Issue.ProjectID), uint(payload.IssuePayload.Issue.IID), commentMsg)
				if err != nil {
					utils.ErrorPrint("CommentFailed", err.Error())
				}
			}
			//! Gitlab评论方式通知更新情况
		case glbapi.CommentApprovalReject:
			// （更新）Ticket记录
			targetStats := []string{
				common.PreCheckSuccessStatus,
			}
			// （更新）Ticket记录
			var tk dbo.Ticket
			err := tk.ValidateAndUpdateStatus(dbo.Ticket{
				ProjectID: int(payload.IssuePayload.Issue.ProjectID),
				IssueID:   int(payload.IssuePayload.Issue.IID),
			}, common.ApprovalRejectStatus, targetStats...)
			if err != nil {
				commentMsg := fmt.Sprintf("[UpdateTicketErr] **%s**", err.Error())
				err := glab.CommentCreate(uint(payload.IssuePayload.Issue.ProjectID), uint(payload.IssuePayload.Issue.IID), commentMsg)
				if err != nil {
					utils.ErrorPrint("CommentFailed", err.Error())
				}
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
		// 由Issue标识唯一全局ID
		uuid := utils.GenerateUUIDKey()
		// （创建）Ticket记录
		sourceRef := fmt.Sprintf("gitlab:%d:%d:%d", userId, payload.Issue.ProjectID, payload.Issue.IID)
		ticket := dbo.Ticket{
			UID:       uuid,
			Status:    common.CreatedStatus,
			SourceRef: sourceRef,
			AuthorID:  int(userId),
			ProjectID: int(payload.Issue.ProjectID),
			IssueID:   int(payload.Issue.IID),
			Link:      payload.Issue.URL,
			Source:    "gitlab",
		}
		err := ticket.LastAndCreateOrUpdate()
		if err != nil {
			commentMsg := fmt.Sprintf("[TicketErr] **%s**", err.Error())
			err := glab.CommentCreate(uint(payload.Issue.ProjectID), uint(payload.Issue.IID), commentMsg)
			if err != nil {
				utils.ErrorPrint("CommentFailed", err.Error())
			}
		}
		t, err := ticket.FindOne(dbo.Ticket{
			SourceRef: sourceRef,
		})
		if err != nil {
			commentMsg := fmt.Sprintf("[TicketErr] **%s**", err.Error())
			err := glab.CommentCreate(uint(payload.Issue.ProjectID), uint(payload.Issue.IID), commentMsg)
			if err != nil {
				utils.ErrorPrint("CommentFailed", err.Error())
			}
		}
		//TODO：是否区分Issue不同操作的逻辑

		// 缓存issue信息，若找不到则从数据库中查找。
		issCache := &glbapi.IssueCache{
			Content: payload.Desc,
			Issue:   payload.Issue,
		}
		GitLabIssueMap.Set(t.UID, issCache, common.TicketCacheMapDDL, common.IssueTicketType)
		fmt.Println("Issue cache", issCache.Content.Statement, issCache)
		// 更新详情内容(GitLab)
		commentMsg := fmt.Sprintf("[Ticket_ID] **%s**, 准备预检...", t.UID)
		err = glab.CommentCreate(uint(payload.Issue.ProjectID), uint(payload.Issue.IID), commentMsg)
		if err != nil {
			utils.ErrorPrint("CommentFailed", err.Error())
		}

		// 准备进入预检阶段。(分别从Issue和IssueContent进行提取)
		ep := event.GetEventProducer()
		ep.Produce(event.Event{
			Type: "sql_check",
			Payload: &CheckEvent{
				GID:      t.UID,
				TicketID: t.UID,
				UserID:   int(userId),
			},
		})
	}
	return nil
}

// 检查事件(用于检查SQL阶段)
type PreCheckEventHandler struct {
}

func NewCheckEventHandler() event.EventHandler {
	return &PreCheckEventHandler{}
}

func (eh *PreCheckEventHandler) Name() string {
	return "检查事件处理者"
}

func (eh *PreCheckEventHandler) Work(ctx context.Context, e event.Event) error {
	errCh := make(chan error, 1)
	ep := event.GetEventProducer()
	preCheckRes := &PreCheckResultGroup{
		Data: &PreCheckResult{
			ParsedSQL: make([]SQLForParseV2, 0),
			Explain: ExplainCheck{
				Results: make([]dbo.SQLResult, 0),
			},
			Soar: SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}
	switch p := e.Payload.(type) {
	case *CheckEvent:
		fmt.Println("debug print pre-check starting....")
		// 预先设置结果基本项数据
		preCheckRes.GID = p.GID
		preCheckRes.Data.TicketID = p.TicketID
		// goroutine
		go func(context.Context) {
			// 获取Issue信息
			val, exist := GitLabIssueMap.Get(p.GID)
			if !exist {
				errCh <- utils.GenerateError("GitLabIssueNotExist", "Issue Cache is not exist"+p.GID)
				return
			}
			issCache, ok := val.(*glbapi.IssueCache)
			if !ok {
				errCh <- utils.GenerateError("GitLabIssueInvalid", "Issue Cache type is invalid")
				return
			}

			// 更新Ticket信息(正在处理预检)
			targetStats := []string{
				common.CreatedStatus,
				common.EditedStatus,
				common.ReInitedStatus,
			}
			// err := p.CheckTicketStats(targetStats)
			// if err != nil {
			// 	errCh <- err
			// 	return
			// }
			err := p.UpdateTicketStats(common.PreCheckingStatus, targetStats...)
			if err != nil {
				errCh <- err
				return
			}
			// 解析SQL
			parseStmts, err := ParseV3(issCache.Content.Statement)
			if err != nil {
				errCh <- err
				return
			}
			preCheckRes.Data.ParsedSQL = parseStmts

			// EXPLAIN解析
			ist, err := dbo.HaveDBIst(issCache.Content.Env, issCache.Content.DBName, issCache.Content.Service)
			if err != nil {
				errCh <- err
				return
			}
			explainResult := make([]dbo.SQLResult, 0)
			for _, stmt := range parseStmts {
				explainResult = append(explainResult, ist.Explain(ctx, stmt.SafeStmt, p.GID))
			}
			preCheckRes.Data.Explain.Results = explainResult

			// TODO：SOAR 分析（利用系统层面SOAR操作实现，捕获屏幕输出流）
			if issCache.Content.IsSoarAnalysis {
				soar := NewSoarAnalyzer(
					WithReportFormat("json"),
					WithSQLContent(issCache.Content.Statement),
					WithCommandPath("/tmp"),
					WithCommand("soar.linux-amd64_v11"),
				)
				soarResult, err := soar.Analysis()
				if err != nil {
					errCh <- err
					return
				}
				fmt.Println("soar result:", soarResult)
				preCheckRes.Data.Soar.Results = soarResult
			}

			// TODO：是否要加入SELECT COUNT(*)的数据量对比

			// 自定义规则解析
			// 1. 检查黑名单（数据库和数据表）
			dbPool := dbo.GetDBPoolManager()
			illegalDBs := dbPool.ExcludeDBList()
			for _, stmt := range parseStmts {
				for _, f := range stmt.From {
					// 需要处理派生表的情况（subFrom出现违规表)
					if slices.Contains(illegalDBs, f.DBName) {
						errCh <- utils.GenerateError("IllegalTable", f.DBName+" SQL DB Name is illegal")
						return
					}
				}
			}
			illegalTables := ist.ExcludeTableList()
			// 普通不全版
			for _, stmt := range parseStmts {
				for _, f := range stmt.From {
					// 需要处理派生表的情况（subFrom出现违规表)
					if slices.Contains(illegalTables, f.TableName) {
						errCh <- utils.GenerateError("IllegalTable", f.TableName+" SQL Table Name is illegal")
						return
					}
				}
			}
			// 递归版
			// var recu func([]FromParse)
			// for _, stmt := range parseStmts {
			// 	recu = func([]FromParse) {
			// 		for _, f := range stmt.From {
			// 			// 需要处理派生表的情况（subFrom出现违规表)
			// 			if slices.Contains(illegalTables, f.TableName) {
			// 				errCh <- utils.GenerateError("IllegalTable", f.TableName+" SQL Table Name is illegal")
			// 				return
			// 			}
			// 			if f.IsDerivedTable {
			// 				recu(f.SubFrom)
			// 			}
			// 		}
			// 	}
			// }

			// 更新Ticket信息
			err = p.UpdateTicketStats(common.PreCheckSuccessStatus)
			if err != nil {
				errCh <- err
				return
			}
			// 表示正常完成（!）
			errCh <- nil

		}(ctx)
		// 统一错误处理
		select {
		case err := <-errCh:
			if err != nil {
				preCheckRes.Errrr = err
				ep.Produce(event.Event{
					Type:    "save_result",
					Payload: preCheckRes,
				})
				// 更新Ticket信息
				err = p.UpdateTicketStats(common.PreCheckFailedStatus)
				if err != nil {
					utils.ErrorPrint("TicketStatsErr", "Update Ticket Status is failed")
				}
				return nil
			}
			//! 展示预检成功的结果详情。
			fmt.Println("debug print pre-check completed")
			ep.Produce(event.Event{
				Type:    "save_result",
				Payload: preCheckRes,
			})
		case <-ctx.Done():
			utils.ErrorPrint("GoroutineErr", "goroutine is error")
		}
	}
	return nil
}
