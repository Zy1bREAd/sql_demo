package core

import (
	"context"
	"fmt"
	"log"
	"reflect"
	api "sql_demo/api"
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
		}
		for k, handler := range registerMap {
			err := ed.RegisterHandler(k, handler(), 3)
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
		utils.DebugPrint("SQL查询事件消费", t.ID)
		QueryTaskMap.Set(t.ID, t, 300, 1) // 存储查询任务信息
		t.ExcuteTask(ctx)
		// 日志审计插入v2（不支持）

	case *QTaskGroup: // 支持多SQL
		utils.DebugPrint("SQL查询Group事件消费", t.GID)
		QueryTaskMap.Set(t.GID, t, 300, 1)
		t.ExcuteTask(ctx)

	case *IssueQTask:
		utils.DebugPrint("GItlab Issue SQL查询事件消费", t.QTG.GID)
		QueryTaskMap.Set(t.QTG.GID, t, 300, 1) // 存储查询任务信息
		// Issue评论情况更新并开始执行任务
		glab := InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskId=%s is start work...", t.QTG.GID)
		glab.CommentCreate(t.QIssue.ProjectID, t.QIssue.IID, updateMsg)

		t.QTG.ExcuteTask(ctx)
		// 日志审计插入v2
		audit := dbo.AuditRecordV2{
			TaskID:    t.QTG.GID,
			UserID:    t.QTG.UserId,
			Payload:   t.QIssue.Description,
			ProjectID: t.QIssue.ProjectID,
			IssueID:   t.QIssue.IID,
		}
		err := audit.InsertOne("SQL_QUERY")
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
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
		v, ok := val.(*IssueQTask)
		if !ok {
			return nil
		}
		// Issue评论情况更新
		glab := InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskGId=%s is completed", res.GID)
		glab.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, updateMsg)
		for _, result := range res.ResGroup {
			if result.Errrrr != nil {
				errMsg := fmt.Sprintf("- TaskGId=%s\n- IID=%s\n- TaskError=%s", res.GID, result.ID, result.ErrMsg)
				err := glab.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, errMsg)
				if err != nil {
					utils.DebugPrint("CommentError", "query task result comment is failed"+err.Error())
				}
				// break
				return nil
			}
		}
		// 存储结果、输出结果临时链接
		issContent, err := ParseIssueDesc(v.QIssue.Description)
		if err != nil {
			glab.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, "export result file is failed, "+err.Error())
		}
		uuKey, tempURL := NewHashTempLink()
		err = dbo.SaveTempResult(uuKey, res.GID, 300, issContent.IsExport)
		if err != nil {
			utils.DebugPrint("SaveTempResultError", "db save result link is failed "+err.Error())
		}
		glab.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, tempURL)
		// 导出结果(同步)
		if issContent.IsExport {
			exportTask := SubmitExportTask(res.GID, "csv", v.QIssue.Author.ID)
			<-exportTask.Result.Done
		}
		// 自动关闭issue（表示完成）
		err = glab.IssueClose(v.QIssue.ProjectID, v.QIssue.IID)
		if err != nil {
			utils.DebugPrint("GitLabAPIError", err.Error())
		}
		// 完成通知
		iss, err := glab.IssueView(v.QIssue.ProjectID, v.QIssue.IID)
		if err != nil {
			utils.DebugPrint("GitLabAPIError", err.Error())
		}
		informBody := api.InformTemplate{
			UserName: v.QIssue.Author.Name,
			Action:   "Completed",
			Link:     iss.WebURL,
		}
		_ = api.InformRobot(informBody.Fill())
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
	body, ok := e.Payload.(*ExportTask)
	if !ok {
		return utils.GenerateError("TypeError", "event payload type is incrroect")
	}
	//! 后期核心处理结果集的代码逻辑块
	utils.DebugPrint("ExportTask", "export task "+body.ID+" is starting...")
	err := ExportSQLTask(ctx, body)
	if err != nil {
		// 添加错误信息
		body.Result.Error = err
		body.Result.FilePath += "_failed"
		body.Result.Done <- struct{}{}
		utils.DebugPrint("ExportTask", "export task "+body.ID+" is failed,error: "+err.Error())
		return nil
	}
	utils.DebugPrint("ExportTask", "export task "+body.ID+" is completed")
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
	utils.DebugPrint("文件清理事件消费", body.ID)
	//! 后期核心处理结果集的代码逻辑块
	FileClean(body.Result.FilePath)
	return nil
}
