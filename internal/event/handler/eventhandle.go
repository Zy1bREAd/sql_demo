package event

import (
	"context"
	"fmt"
	"log"
	"reflect"
	glbapi "sql_demo/internal/clients/gitlab"
	"sql_demo/internal/common"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/services"

	// "sql_demo/internal/services"
	"sql_demo/internal/utils"
	"sync"
)

var eventOnce sync.Once

func InitEventDrive(ctx context.Context, bufferSize int) {
	ep := event.GetEventProducer()
	ed := event.GetEventDispatcher()
	eventOnce.Do(func() {
		ep.Init(bufferSize)
		ed.Init(3, bufferSize)
		// 调度者的Handler初始化
		registerMap := map[string]func() event.EventHandler{
			"sql_query":         NewQueryEventHandler,
			"save_result":       NewResultEventHandler,
			"clean_task":        NewCleanEventHandler,
			"export_result":     NewExportEventHandler,
			"file_housekeeping": NewHousekeepingEventHandler,
			"gitlab_webhook":    NewGitLabEventHandler,
			"sql_check":         NewCheckEventHandler,
		}
		for k, handler := range registerMap {
			err := ed.RegisterHandler(k, handler(), 5)
			if err != nil {
				panic(err)
			}
		}
	})
	// 启动调度者开始调度事件
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
	case *core.QTaskGroupV2:
		apiSrv := services.NewAPITaskService(
			services.WithAPITaskBusinessRef(e.MetaData.TraceID),
			services.WithAPITaskUserID(string(t.UserID)),
		)
		err := apiSrv.Excute(ctx, t)
		return err

	case *core.IssueQTaskV2:
		// 获取Service层操作对象
		gitlabSrv := services.NewGitLabTaskService(
			services.WithGitLabTaskProjectID(t.IssProjectID),
			services.WithGitLabTaskIssueIID(t.IssIID),
			services.WithGitLabTaskUserID(t.QTG.UserID),
			services.WithGitLabTaskUID(t.QTG.TicketID),
		)
		err := gitlabSrv.Excute(ctx, t)
		return err
	default:
		return utils.GenerateError("UnknownTask", "Task Event Kind is Unknown")
	}

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
		utils.DebugPrint("SQLResult查询结果事件消费", res.ID)
	case *core.PreCheckResultGroup:
		switch e.MetaData.Source {
		case "gitlab":
			// 核心数据获取，TicketID（一切的前提）
			gitlabSrv := services.NewGitLabTaskService(services.WithGitLabTaskUID(res.TicketID))
			return gitlabSrv.SaveCheckData(ctx, res)
		case "api":
			apiSrv := services.NewAPITaskService(services.WithAPITaskTaskUID(res.TicketID))
			return apiSrv.SaveCheckData(ctx, res)
		default:
			utils.DebugPrint("UnknownSource", "未知请求源")
		}

	case *core.SQLResultGroupV2:
		switch e.MetaData.Source {
		case "gitlab":
			// 核心数据获取，TicketID（一切的前提）
			gitlabSrv := services.NewGitLabTaskService(services.WithGitLabTaskUID(res.TicketID))
			err := gitlabSrv.SaveResult(ctx, res)
			if err != nil {
				utils.ErrorPrint("EventError", err.Error())
			}
		case "api":
			apiSrv := services.NewAPITaskService(services.WithAPITaskTaskUID(res.TicketID),
				services.WithAPITaskBusinessRef(e.MetaData.TraceID))
			err := apiSrv.SaveResult(ctx, res)
			if err != nil {
				utils.ErrorPrint("EventError", err.Error())
			}
		default:
			utils.DebugPrint("UnknownSource", "未知请求源")
		}

	default:
		typeName := reflect.TypeOf(e.Payload)
		log.Println("没有匹配到的结果集类型", typeName)
	}
	return nil
}

type CleanEventHandler struct {
	cleanTypeMap     map[int]*core.CachesMap
	cleanTypeInfoMap map[int]string
}

func NewCleanEventHandler() event.EventHandler {

	return &CleanEventHandler{
		cleanTypeMap: map[int]*core.CachesMap{
			0: core.ResultMap,
			1: core.QueryTaskMap,
			2: core.SessionMap,
			3: core.ExportWorkMap,
			4: core.CheckTaskMap,
			5: core.DoubleCheckTaskMap,
			6: core.APITaskBodyMap,
		},
		cleanTypeInfoMap: map[int]string{
			0: "ResultMap",
			1: "QueryTaskMap",
			2: "SessionMap",
			3: "ExportWorkMap",
			4: "CheckTaskMap",
			5: "DoubleCheckTaskMap",
			6: "APITaskBodyMap",
		},
	}
}

func (eh *CleanEventHandler) Name() string {
	return "清理事件处理者"
}

func (eh *CleanEventHandler) Work(ctx context.Context, e event.Event) error {
	body, ok := e.Payload.(core.CleanTask)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	utils.DebugPrint("清理结果事件消费", body.ID)
	//! 后期核心处理结果集的代码逻辑块
	mapOperator, ok := eh.cleanTypeMap[body.Kind]
	if !ok {
		utils.ErrorPrint("UnknownCleanFlag", "Unknown Clean Task Kind."+string(body.Kind))
		return nil
	}
	mapOperator.Del(body.ID)
	log.Printf("type=%v taskID=%d Cleaned Up", eh.cleanTypeInfoMap[body.Kind], body.ID)
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
	export, ok := e.Payload.(*services.ExportEvent)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	utils.DebugPrint("ExportTask", fmt.Sprintf("Task:%s is Starting...", export.TaskID))
	exportSrv := services.NewExportResultService(
		services.WithExportUserID(uint(e.MetaData.Operator)),
		services.WithExportIsOnly(export.IsOnly),
	)
	err := exportSrv.Export(ctx, export)
	if err != nil {
		utils.ErrorPrint("EventWorkerErr", err.Error())
	}
	utils.DebugPrint("ExportTask", fmt.Sprintf("Task:%s is Completed", export.TaskID))
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
	body, ok := e.Payload.(*services.ExportEvent)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	utils.DebugPrint("文件清理事件消费", body.TaskID)
	//! 后期核心处理结果集的代码逻辑块
	utils.FileClean(body.FilePath)
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
	errCh := make(chan error, 1)
	var commentBody glbapi.GitLabComment
	body, ok := e.Payload.(*services.GitLabWebhook)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	glab := glbapi.InitGitLabAPI()

	// 审批or驳回or上线 逻辑
	switch body.Webhook {
	case services.CommentHandle:
		payload, ok := body.Payload.(*services.CommentPayload)
		if !ok {
			return utils.GenerateError("PayloadErr", "payload is invalid")
		}
		commentBody.ProjectID = payload.IssuePayload.Issue.ProjectID
		commentBody.IssueIID = payload.IssuePayload.Issue.IID
		// 获取USer真实ID
		user := dbo.User{
			GitLabIdentity: payload.IssuePayload.Issue.AuthorID,
		}
		userId := user.GetGitLabUserId()
		// 获取Service层操作对象
		gitlabSrv := services.NewGitLabTaskService(
			services.WithGitLabTaskProjectID(commentBody.ProjectID),
			services.WithGitLabTaskIssueIID(commentBody.IssueIID),
			services.WithGitLabTaskUserID(userId),
		)
		// (关键)通过Issue信息获取Ticket UID
		tkUID := gitlabSrv.GetTicketUID()
		gitlabSrv.UID = tkUID
		go func(context.Context) {

			switch payload.Action {
			case services.CommentOnlineExcute: //! 执行上线
				err := gitlabSrv.ActionHandle(ctx, common.OnlineActionFlag)
				if err != nil {
					errCh <- err
					return
				}
				//! Gitlab评论方式通知更新情况
				_ = glab.CommentCreate(glbapi.GitLabComment{
					ProjectID: commentBody.ProjectID,
					IssueIID:  commentBody.IssueIID,
					Message:   "上线成功,开始执行...",
				})

			case services.CommentApprovalPassed: // ! 审批通过
				err := gitlabSrv.ActionHandle(ctx, common.ApprovalActionFlag)
				if err != nil {
					errCh <- err
					return
				}
				//! Gitlab评论方式通知更新情况
				_ = glab.CommentCreate(glbapi.GitLabComment{
					ProjectID: commentBody.ProjectID,
					IssueIID:  commentBody.IssueIID,
					Message:   "审批成功, 等待上线...",
				})

			case services.CommentApprovalReject: // ! 驳回
				err := gitlabSrv.ActionHandle(ctx, common.RejectActionFlag)
				if err != nil {
					errCh <- err
					return
				}
				//! Gitlab评论方式通知更新情况
				_ = glab.CommentCreate(glbapi.GitLabComment{
					ProjectID: commentBody.ProjectID,
					IssueIID:  commentBody.IssueIID,
					Message:   "【驳回】" + payload.Reason,
				})
			default:
				errCh <- utils.GenerateError("CommentActionErr", "comment action is unknow type")
			}
		}(ctx)
	case services.IssueHandle: //! 创建 Issue
		payload, ok := body.Payload.(*services.IssuePayload)
		if !ok {
			return utils.GenerateError("PayloadErr", "payload is invalid")
		}
		commentBody.ProjectID = payload.Issue.ProjectID
		commentBody.IssueIID = payload.Issue.IID
		//! Gitlab创建SQLTask和Ticket
		go func(context.Context) {
			gitlabTask := services.NewGitLabTaskService()
			// TODO: 后续增加上下文ctx，超时控制
			_, err := gitlabTask.Create(payload)
			errCh <- err
		}(ctx)
	}

	select {
	case err := <-errCh:
		if err != nil {
			// 统一错误处理
			retryErr := glab.Retry(3, func() error {
				return glab.CommentCreate(glbapi.GitLabComment{
					ProjectID: commentBody.ProjectID,
					IssueIID:  commentBody.IssueIID,
					Message:   err.Error(),
				})
			})
			if retryErr != nil {
				utils.ErrorPrint("CommentFailed", retryErr.Error())
				return retryErr
			}
			return nil
		}
	case <-ctx.Done():
		utils.ErrorPrint("GoroutineErr", "goroutine is break off(interrupted)")
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
	var tasker services.TaskServicer
	errCh := make(chan error, 1)
	ep := event.GetEventProducer()
	preCheckRes := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}
	switch p := e.Payload.(type) {
	case *services.FristCheckEventV2:
		// 预先设置结果基本项数据
		preCheckRes.TicketID = p.TicketID
		switch e.MetaData.Source {
		case "gitlab":
			go func(parentCtx context.Context) {
				gitlabSrv := services.NewGitLabTaskService(services.WithGitLabTaskUID(p.TicketID),
					services.WithGitLabTaskProjectID(e.MetaData.ProjectID),
					services.WithGitLabTaskIssueIID(e.MetaData.IssueIID),
				)
				tasker = gitlabSrv
				err := gitlabSrv.FristCheck(parentCtx, preCheckRes)
				if err != nil {
					errCh <- err
					return
				}
				// 表示正常完成（!）
				errCh <- nil
			}(ctx)

		case "api":
			go func(parentCtx context.Context) {
				apiSrv := services.NewAPITaskService(services.WithAPITaskTaskUID(p.TicketID), services.WithAPITaskBusinessRef(p.Ref))
				tasker = apiSrv
				err := apiSrv.FristCheck(parentCtx, preCheckRes)
				if err != nil {
					utils.DebugPrint("PreCheckErr", err.Error())
					errCh <- err
					return
				}
				errCh <- nil // 表示正常完成（!）

			}(ctx)
		default:
			utils.DebugPrint("UnknownSource", "未知请求源")
		}
	}

	// 统一错误处理
	select {
	case err := <-errCh:
		if err != nil {
			preCheckRes.ErrMsg = err.Error()
			ep.Produce(event.Event{
				Type:     "save_result",
				Payload:  preCheckRes,
				MetaData: e.MetaData,
			})

			err = tasker.UpdateTicketStats(common.PreCheckFailedStatus)
			if err != nil {
				utils.ErrorPrint("TicketStatsErr", "Update Ticket Status is failed")
			}
			return nil
		}
		//! 存储展示预检结果详情。
		ep.Produce(event.Event{
			Type:     "save_result",
			Payload:  preCheckRes,
			MetaData: e.MetaData,
		})

	case <-ctx.Done():
		utils.ErrorPrint("GoroutineErr", "goroutine is error,break off!")
	}
	return nil
}
