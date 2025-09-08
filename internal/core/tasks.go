package core

import (
	"context"
	"encoding/json"
	"fmt"

	"sql_demo/internal/conf"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"time"
)

const (
	ReExcuteFlag    = true
	NotReExcuteFlag = false
)

type ReExcute struct {
	isReExcute bool
	deadline   int
}

type ExportResult struct {
	Done     chan struct{} `json:"-"`
	FilePath string
	Error    error `json:"-"`
}

type ExportTask struct {
	UserID    uint
	ResultIdx int    `json:"result_idx" query:"result_idx"` // 用于仅导出指定结果集的索引（前端传递）
	deadline  int    // task timeout
	IsOnly    bool   `json:"is_only" query:"is_only"`
	GID       string `json:"task_id" query:"task_id"`
	IID       string `json:"sql_id" query:"sql_id"`
	FileName  string

	Result *ExportResult
}

func (et *ExportTask) GetResult() error {
	val, exist := ExportWorkMap.Get(et.GID)
	if !exist {
		return utils.GenerateError("ResultsError", "ExportTask is not exist")
	}
	resultVal, ok := val.(*ExportResult)
	if !ok {
		return utils.GenerateError("ResultsError", "ExportTask type is not match")
	}
	et.Result = resultVal
	return nil
}

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

type cleanTask struct {
	Type int // 清理类型(0 and 1)
	ID   string
}

type QTasker interface {
	Execute()
}

type QueryTask struct {
	ID       string
	Deadline int // 单个SQL的超时时间（单位为秒）
	SafeSQL  SQLForParse
}
type QTaskGroup struct {
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
	QTasks   []*QueryTask
}

// 封装QueryTask 结合GitLab Issue
type IssueQTask struct {
	QTG           *QTaskGroup
	IssProjectID  uint
	IssIID        uint
	IssAuthorID   uint
	IssAuthorName string
	// IssDesc       *gapi.SQLIssueTemplate
}

// 多SQL执行(可Query可Excute), 遇到错误立即退出后续执行
func (qtg *QTaskGroup) ExcuteTask(ctx context.Context) {
	utils.DebugPrint("TaskDetails", fmt.Sprintf("Task GID=%s is working...", qtg.GID))
	//! 执行任务函数只当只关心任务处理逻辑本身

	ep := event.GetEventProducer()
	rg := &dbo.SQLResultGroup{
		GID:      qtg.GID,
		ResGroup: make([]*dbo.SQLResult, 0),
	}

outerLoop:
	for _, task := range qtg.QTasks {
		// 子任务超时控制
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(task.Deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
		defer cancel()
		utils.DebugPrint("TaskDetails", fmt.Sprintf("Task IID=%s is working...", task.ID))
		var result dbo.SQLResult = dbo.SQLResult{
			ID:   task.ID,
			Stmt: task.SafeSQL.SafeStmt,
		}
		// 获取对应数据库实例进行SQL查询
		op, err := dbo.HaveDBIst(qtg.Env, qtg.DBName, qtg.Service)
		if err != nil {
			result.Errrrr = err
			result.ErrMsg = result.Errrrr.Error()
			rg.ResGroup = append(rg.ResGroup, &result)
			break
		}
		// 检查黑名单表名
		for _, illegal := range op.ExcludeTableList() {
			if task.SafeSQL.Table != illegal {
				continue
			}
			result.Errrrr = utils.GenerateError("TaskPreCheck", task.SafeSQL.Table+" SQL Table Name is illegal")
			result.ErrMsg = result.Errrrr.Error()
			rg.ResGroup = append(rg.ResGroup, &result)
			break outerLoop
		}
		// 执行前健康检查DB
		err = op.HealthCheck(timeoutCtx)
		if err != nil {
			result.Errrrr = utils.GenerateError("HealthCheckFailed", err.Error())
			result.ErrMsg = result.Errrrr.Error()
			rg.ResGroup = append(rg.ResGroup, &result)
			break
		}
		// 主要分查询和执行，核心通过解析SQL语句的类型来实现对应的逻辑
		if task.SafeSQL.Action == "select" {
			result = op.Query(timeoutCtx, task.SafeSQL.SafeStmt, task.ID, conf.DataMaskHandle)
		} else {
			result = op.Excute(timeoutCtx, task.SafeSQL.SafeStmt, task.ID)
		}

		rg.ResGroup = append(rg.ResGroup, &result)
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

func (et *ExportTask) Submit() {
	auditCh := make(chan struct{}, 1)
	today := time.Now().Format("20060102150405")
	conf := conf.GetAppConf().GetBaseConfig()
	// 异步插入记录V2
	go func() {
		// 获取Issue详情(使用taskId和UserId来查找对应的issue)
		var auditRecord dbo.AuditRecordV2
		dbConn := dbo.HaveSelfDB().GetConn()
		res := dbConn.Where("task_id = ?", et.GID).First(&auditRecord)
		if res.Error != nil {
			utils.ErrorPrint("DBAPIError", res.Error.Error())
			return
		}
		if res.RowsAffected != 1 {
			utils.ErrorPrint("DBAPIError", "rows is zero")
			return
		}
		// 日志审计插入v2
		auditRecord.ID = 0
		auditRecord.UserID = et.UserID
		// 更换导出详细的Payload
		exportPayload, err := json.Marshal(&et)
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
			return
		}
		auditRecord.Payload = string(exportPayload)
		auditRecord.CreateAt = time.Now()

		err = auditRecord.InsertOne("RESULT_EXPORT")
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
			return
		}
		auditCh <- struct{}{}
	}()
	// 构造导出任务（默认5分钟清理）
	taskResult := &ExportResult{
		Error: nil,
		Done:  make(chan struct{}),
	}
	// 确定完整的文件名（包含后缀）
	if et.IsOnly {
		fileName := fmt.Sprintf("result_export_%s_%s", et.GID, today)
		et.FileName = fileName + ".csv"
		taskResult.FilePath = conf.ExportEnv.FilePath + "/" + et.FileName
	} else {
		fileName := fmt.Sprintf("result_export_all_%s_%s", et.GID, today)
		et.FileName = fileName + ".xlsx"
		taskResult.FilePath = conf.ExportEnv.FilePath + "/" + et.FileName
	}
	et.Result = taskResult
	et.deadline = 300
	ExportWorkMap.Set(et.GID, et.Result, 300, 3)
	// 确保审计完成
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type:    "export_result",
		Payload: et,
	})
}

// 导出SQL查询结果
func (et *ExportTask) Export(ctx context.Context) error {
	// var cachesMapResult *dbo.SQLResultGroup
	if et.GID == "" {
		return utils.GenerateError("TaskNotExist", "task id is not found")
	}
	// 获取任务结果集
	taskResults, err := getTaskResults(ctx, et.GID, ReExcute{
		isReExcute: ReExcuteFlag,
		deadline:   et.deadline,
	})
	if err != nil {
		return err
	}
	conf := conf.GetAppConf().GetBaseConfig()
	if et.IsOnly {
		// 仅导出
		csvRes := utils.CSVResult{
			BasePath: conf.ExportEnv.FilePath,
			FileName: et.FileName,
			Data:     taskResults.ResGroup[et.ResultIdx].Results,
		}

		err := csvRes.Convert()
		if err != nil {
			return err
		}
	} else {
		// 导出全部
		excelRes := utils.ExcelResult{
			BasePath: conf.ExportEnv.FilePath,
			FileName: et.FileName,
		}
		err := excelRes.CreateFile()
		if err != nil {
			return err
		}
		for index, result := range taskResults.ResGroup {
			excelRes.Data = result.Results
			excelRes.Index = index + 1
			err := excelRes.Convert()
			if err != nil {
				return err
			}
		}
	}
	// 等待清理（goroutine）
	time.AfterFunc(time.Second*time.Duration(conf.ExportEnv.HouseKeeping), func() {
		// HouseKeepQueue <- task
		ep := event.GetEventProducer()
		ep.Produce(event.Event{
			Type:    "file_housekeeping",
			Payload: et,
		})
	})
	et.Result.Done <- struct{}{}
	return nil
}

func (et *ExportTask) Clean(ctx context.Context) {
	utils.FileClean(et.Result.FilePath)
}

// 获取结果集（设置是否需要重做flag），返回结果集和error
// 检查结果集resultMap还是否存在当前task的result，来决定是否重新执行查询任务来获取结果
func getTaskResults(ctx context.Context, taskId string, re ReExcute) (*dbo.SQLResultGroup, error) {
	mapVal, resultExist := ResultMap.Get(taskId)
	if !resultExist {
		taskMap, taskExist := QueryTaskMap.Get(taskId)
		if !taskExist {
			return nil, utils.GenerateError("QueryTaskError", "task id is not exist,please re-excute sql query")
		}
		switch t := taskMap.(type) {
		case *QueryTask:
			utils.ErrorPrint("ExportSQLTask", "the QueryTask is not supported")
		case *QTaskGroup:
			t.ExcuteTask(ctx)
		default:
			return nil, utils.GenerateError("QueryTaskError", "query task object type not match")
		}
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= int(re.deadline); i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(taskId)
			if ok {
				assertVal, ok := mapVal.(*dbo.SQLResultGroup)
				if !ok {
					return nil, utils.GenerateError("QueryResultError", "query result data type is incorrect")
				}
				utils.DebugPrint("ReExcuteTask", "re-excute query task is sucess")
				return assertVal, nil
			}
		}
		return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeout")
	}
	assertVal, ok := mapVal.(*dbo.SQLResultGroup)
	if !ok {
		return nil, utils.GenerateError("QueryResultError", "query result data type is incorrect")
	}
	return assertVal, nil
}
