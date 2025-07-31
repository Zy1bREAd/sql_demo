package core

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"sql_demo/internal/conf"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"time"
)

type ExportResult struct {
	Done     chan struct{}
	FilePath string
	Error    error
}

type ExportTask struct {
	ID       string `json:"task_id"`
	Type     string `json:"export_type"`
	FileName string
	UserID   uint
	deadline int // task timeout
	Result   *ExportResult
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
	ID        string
	Action    string // 表示SQL执行的DML
	Statement string
	Deadline  int // 单个SQL的超时时间（单位为秒）

}
type QTaskGroup struct {
	UserID   uint // 关联执行用户id
	Deadline int  //整个任务组的超时时间
	GID      string
	DML      string
	Env      string // 所执行环境
	DBName   string
	Service  string
	StmtRaw  string // 原生的SQL语句
	IsExport bool
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

// 提交SQL查询任务入队(v1.0)
// func SubmitSQLTask(statement string, database string, userId string) string {
// 	//! context控制超时
// 	task := &QueryTask{
// 		ID:        GenerateUUIDKey(),
// 		DBName:    database,
// 		Statement: statement,
// 		deadline:  12,
// 		UserID:    StrToUint(userId),
// 	}
// 	TaskQueue <- task
// 	log.Printf("task id=%s is enqueue", task.ID)
// 	return task.ID
// }

// 事件驱动(v2.0)
// func CreateSQLQueryTask(statement string, database string, userId string) QueryTask {
// 	//! context控制超时
// 	task := QueryTask{
// 		ID:        GenerateUUIDKey(),
// 		DBName:    database,
// 		Statement: statement,
// 		deadline:  30,
// 	}
// 	log.Printf("task id=%s is enqueue", task.ID)
// 	return task
// }

// 多SQL执行(可Query可Excute), 遇到错误立即退出后续执行
func (qtg *QTaskGroup) ExcuteTask(ctx context.Context) {
	log.Printf("task group_id=%s is working", qtg.GID)
	//! 执行任务函数只当只关心任务处理逻辑本身
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(qtg.Deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
	defer cancel()

	ep := event.GetEventProducer()
	rg := &dbo.SQLResultGroup{
		GID:      qtg.GID,
		ResGroup: make([]*dbo.SQLResult, 0),
	}
	for _, task := range qtg.QTasks {
		var result dbo.SQLResult = dbo.SQLResult{
			ID:   task.ID,
			Stmt: task.Statement,
		}
		// 获取对应数据库实例进行SQL查询
		op, err := dbo.HaveDBIst(qtg.Env, qtg.DBName, qtg.Service)
		if err != nil {
			result.Errrrr = err
			result.ErrMsg = result.Errrrr.Error()
			rg.ResGroup = append(rg.ResGroup, &result)
			break
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
		if task.Action == "select" {
			result = op.Query(timeoutCtx, task.Statement, task.ID)
		} else {
			result = op.Excute(timeoutCtx, task.Statement, task.ID)
		}
		log.Printf("task group_id=%s iid=%s is completed", rg.GID, task.ID)
		rg.ResGroup = append(rg.ResGroup, &result)
		// 如果该条SQL遇到ERROR立即中止后续执行
		if result.Errrrr != nil {
			break
		}
	}
	ep.Produce(event.Event{
		Type:    "save_result",
		Payload: rg,
	})
}

// 导出任务入队
func SubmitExportTask(id, exportType string, userId uint) *ExportTask {
	today := time.Now().Format("20060102150405")
	conf := conf.GetAppConf().GetBaseConfig()
	filename := fmt.Sprintf("%s_%s.csv", id, today)
	// 避免斜杠重复
	filePath := conf.ExportEnv.FilePath + "/" + filename

	// 构造导出任务（默认5分钟清理）
	taskResult := &ExportResult{
		Error:    nil,
		FilePath: filePath,
		Done:     make(chan struct{}),
	}
	task := &ExportTask{
		ID:       id,
		Type:     exportType,
		deadline: 300,
		FileName: filename,
		UserID:   userId,
		Result:   taskResult,
	}
	ExportWorkMap.Set(task.ID, task.Result, 300, 3)
	// ExportQueue <- task
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type:    "export_result",
		Payload: task,
	})
	return task
}

// 导出SQL查询结果
func ExportSQLTask(ctx context.Context, task *ExportTask) error {
	var cachesMapResult *dbo.SQLResult
	if task.ID == "" {
		return utils.GenerateError("TaskNotExist", "task id is not found")
	}
	// 检查结果集resultMap还是否存在当前task的result
	mapVal, resultExist := ResultMap.Get(task.ID)
	if !resultExist {
		// 从QueryTaskMap中找对应task id的任务信息，重新执行查询任务来获取结果
		taskMap, taskExist := QueryTaskMap.Get(task.ID)
		if !taskExist {
			return utils.GenerateError("QueryTaskError", "query task id is not exist,please re-excute sql query")
		}
		switch t := taskMap.(type) {
		case *QueryTask:
			// t.ExcuteTask(ctx)
			utils.ErrorPrint("NotSupprt", "the QueryTask is not supported.")
		case *QTaskGroup:
			t.ExcuteTask(ctx)
		default:
			return utils.GenerateError("QueryTaskError", "query task object type not match")
		}
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= task.deadline; i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(task.ID)
			if ok {
				assertVal, ok := mapVal.(*dbo.SQLResult)
				if !ok {
					return utils.GenerateError("QueryResultError", "query result data type is incorrect")
				}
				log.Println("[Re-Excute] re-excute sql task completed")
				cachesMapResult = assertVal
				break
			}
		}
	} else {
		assertVal, ok := mapVal.(*dbo.SQLResult)
		if !ok {
			return errors.New("resultData is incorrect type")
		}
		cachesMapResult = assertVal
	}
	conf := conf.GetAppConf().GetBaseConfig()
	switch {
	case task.Type == "csv":
		err := convertCSVFile(conf.ExportEnv.FilePath, task.FileName, cachesMapResult.Results)
		if err != nil {
			return err
		}
		time.AfterFunc(time.Second*time.Duration(conf.ExportEnv.HouseKeeping), func() {
			// HouseKeepQueue <- task
			ep := event.GetEventProducer()
			ep.Produce(event.Event{
				Type:    "file_housekeeping",
				Payload: task,
			})
		})
	default:
		log.Println("[WARN] 暂不支持其他方式导出")
		return utils.GenerateError("TypeError", "export type is unknown")
	}
	// 假装导出要耗时10s
	// time.Sleep(2 * time.Second)
	// 完成后传递<导出结果>对象信息，并通过channel传递完成消息
	task.Result.Done <- struct{}{}
	return nil
}

// 转换成CSV文件并存储在本地
func convertCSVFile(base, filename string, data []map[string]any) error {
	if len(data) <= 0 {
		return utils.GenerateError("ConvertError", "data length is zero")
	}
	// 创建文件，不存在目录则创建
	_, err := os.Stat(base)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(base, 0755)
			if err != nil {
				log.Println("create a file path is failed ->", err.Error())
				return err
			}
		} else {
			log.Println("create a temp CSV file is failed ->", err.Error())
			return err
		}
	}
	filePath := base + "/" + filename
	f, err := os.Create(filePath)
	if err != nil {
		log.Println("create a temp CSV file is failed ->", err.Error())
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// 制造表头
	var headers = make([]string, 0, len(data[0]))
	for key := range data[0] {
		headers = append(headers, key)
	}

	// 写入表头
	if err := w.Write(headers); err != nil {
		log.Println("write headers csv file is error,", err.Error())
		return err
	}

	// 写入结果集数据
	for _, row := range data {
		rowData := toCSVRow(row, headers)
		err := w.Write(rowData)
		if err != nil {
			log.Println("write row data csv file is error,", err.Error())
			return err
		}
	}
	return nil
}

// 提取行数据成切片
func toCSVRow(record map[string]any, headers []string) []string {
	row := make([]string, 0, len(headers))
	for _, col := range headers {
		row = append(row, fmt.Sprintf("%v", record[col]))
	}
	return row
}

// 清理临时文件（如导出文件）
func FileClean(filepath string) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[FileNotExist]", fileInfo.Name(), "is not exist")
			return
		}
		log.Println("[FileError]", err.Error())
		return
	}
	if fileInfo.IsDir() {
		log.Println("[Error]", fileInfo.Name(), "is not a file")
		return
	}
	err = os.Remove(filepath)
	if err != nil {
		log.Println("[RemoveFailed]", fileInfo.Name(), "remove occur a error", err.Error())
	}
	log.Println("[Completed]", fileInfo.Name(), "is cleaned up")
}
