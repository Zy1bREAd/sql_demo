package core

import (
	"context"
	"encoding/json"
	"fmt"

	"sql_demo/internal/common"
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
	IsReExcute bool
	Deadline   int
	Fn         func()
}

type ExportResult struct {
	Done     chan struct{} `json:"-"`
	FilePath string
	Error    error `json:"-"`
}

type ExportTask struct {
	IsOnly    bool `json:"is_only" query:"is_only"`
	UserID    uint
	ResultIdx int    `json:"result_idx" query:"result_idx"` // 用于仅导出指定结果集的索引（前端传递）
	deadline  int    // task timeout
	GID       int64  `json:"task_id" query:"task_id"` // TicketID
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

type CleanTask struct {
	Kind int // 清理类型(0 and 1)
	ID   int64
	UUID string // 标识字符串key
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

func (et *ExportTask) Submit() {
	auditCh := make(chan struct{}, 1)
	today := time.Now().Format("20060102150405")
	conf := conf.GetAppConf().GetBaseConfig()
	// 异步插入记录V2
	go func() {
		// 获取Issue详情(使用taskId和UserId来查找对应的issue)
		var auditRecord dbo.AuditRecordV2
		dbConn := dbo.HaveSelfDB().GetConn()
		res := dbConn.Where("ticket_id = ?", et.GID).Last(&auditRecord)
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

		err = auditRecord.InsertOne(&dbo.AuditRecordV2{})
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
			return
		}
		auditCh <- struct{}{}
	}()
	// 构造导出任务（默认5分钟清理）
	exportRes := &ExportResult{
		Error: nil,
		Done:  make(chan struct{}),
	}
	// 确定完整的文件名（包含后缀）
	if et.IsOnly {
		fileName := fmt.Sprintf("result_export_%d_%s", et.GID, today)
		et.FileName = fileName + ".csv"
		exportRes.FilePath = conf.ExportEnv.FilePath + "/" + et.FileName
	} else {
		fileName := fmt.Sprintf("result_export_all_%d_%s", et.GID, today)
		et.FileName = fileName + ".xlsx"
		exportRes.FilePath = conf.ExportEnv.FilePath + "/" + et.FileName
	}
	et.Result = exportRes
	et.deadline = common.DefaultCacheMapDDL
	ExportWorkMap.Set(et.GID, et.Result, common.DefaultCacheMapDDL, common.ExportWorkMapCleanFlag)
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
	if et.GID == 0 {
		return utils.GenerateError("TaskNotExist", "task id is not found")
	}
	// 获取任务结果集
	taskResults, err := getTaskResults(ctx, et.GID, ReExcute{
		IsReExcute: ReExcuteFlag,
		Deadline:   et.deadline,
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
			Data:     taskResults.Data[et.ResultIdx].Results,
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
		for index, result := range taskResults.Data {
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
func getTaskResults(ctx context.Context, taskId int64, re ReExcute) (*SQLResultGroupV2, error) {
	mapVal, resultExist := ResultMap.Get(taskId)
	if !resultExist {
		taskMap, taskExist := QueryTaskMap.Get(taskId)
		if !taskExist {
			return nil, utils.GenerateError("QueryTaskError", "task id is not exist,please re-excute sql query")
		}
		switch t := taskMap.(type) {
		case *QueryTaskV2:
			utils.ErrorPrint("ExportSQLTask", "the QueryTask is not supported")
		case *QTaskGroupV2:
			t.ExcuteTask(ctx)
		default:
			return nil, utils.GenerateError("QueryTaskError", "query task object type not match")
		}
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= int(re.Deadline); i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(taskId)
			if ok {
				assertVal, ok := mapVal.(*SQLResultGroupV2)
				if !ok {
					return nil, utils.GenerateError("QueryResultError", "query result data type is incorrect")
				}
				utils.DebugPrint("ReExcuteTask", "re-excute query task is sucess")
				return assertVal, nil
			}
		}
		return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeout")
	}
	assertVal, ok := mapVal.(*SQLResultGroupV2)
	if !ok {
		return nil, utils.GenerateError("QueryResultError", "query result data type is incorrect")
	}
	return assertVal, nil
}

// 二次校验：获取结果集（设置是否需要重做flag），返回结果集和error
// 检查结果集resultMap还是否存在当前task的result，来决定是否重新执行查询任务来获取结果
func DoubleCheck(ctx context.Context, ticketID int64, redo ReExcute) (*PreCheckResultGroup, error) {
	cacheVal, exist := CheckTaskMap.Get(ticketID)
	if !exist {
		redo.Fn()
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= redo.Deadline; i++ {
			if !common.CheckCtx(ctx) {
				return nil, utils.GenerateError("GoroutineError", "goroutine is break off(interrupted)")
			}
			time.Sleep(1 * time.Second) // 转成select{}
			mapVal, ok := CheckTaskMap.Get(ticketID)
			if !ok {
				continue
			}
			assertVal, ok := mapVal.(*PreCheckResultGroup)
			if !ok {
				return nil, utils.GenerateError("PreCheckResultError", "pre-check result type is incorrect")
			}
			utils.DebugPrint("ReExcuteTask", "re-excute query task is sucess")
			return assertVal, nil
		}
		// TIMEOUT
		return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeoutttttt")
	}
	// 再次二次检查进行对比
	fristCheck, ok := cacheVal.(*PreCheckResultGroup)
	if !ok {
		return nil, utils.GenerateError("PreCheckResultError", "pre-check result type is incorrect")
	}
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &DoubleCheckEvent{
			FristCheck: fristCheck,
			FristCheckEvent: FristCheckEvent{
				TicketID: ticketID,
			},
		},
	})
	for i := 0; i <= redo.Deadline; i++ {
		if !common.CheckCtx(ctx) {
			return nil, utils.GenerateError("GoroutineError", "goroutine is break off(interrupted)")
		}
		time.Sleep(1 * time.Second)
		mapVal, ok := DoubleCheckTaskMap.Get(ticketID)
		if !ok {
			continue
		}
		doubleCheck, ok := mapVal.(*PreCheckResultGroup)
		if !ok {
			return nil, utils.GenerateError("PreCheckResultError", "pre-check result type is incorrect")
		}
		utils.DebugPrint("DoubleCheck", "double check task is sucess")
		if doubleCheck.Errrr != nil {
			return nil, doubleCheck.Errrr
		}
		//! 对比首次预检检查结果
		for i, analysis := range doubleCheck.Data.ExplainAnalysis {
			for j, val := range analysis.Explain.Results {
				fritst := fristCheck.Data.ExplainAnalysis[i].Explain.Results[j]
				//! (仅Explain type示例)
				if val["type"] == fritst["type"] {
					fmt.Println("debug print::double check ", val["type"])
				}
			}
		}

		return doubleCheck, nil
	}
	// TIMEOUT
	return nil, utils.GenerateError("DoubleCheck", "double check task is timeout")
}
