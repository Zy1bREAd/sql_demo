package apis

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// 维护全局变量
// var TaskQueue chan *QueryTask = make(chan *QueryTask, 30) // 预分配空间
// var ResultQueue chan *QueryResult = make(chan *QueryResult, 30)
// var CleanQueue chan cleanTask = make(chan cleanTask, 30)
// var HouseKeepQueue chan *ExportTask = make(chan *ExportTask, 30)
// var ExportQueue chan *ExportTask = make(chan *ExportTask, 30)
var QueryTaskMap *CachesMap = &CachesMap{cache: &sync.Map{}}   // 存储查询任务相关信息的映射表（任务 -> 详细QueryTask数据)
var ExportWorkMap *CachesMap = &CachesMap{cache: &sync.Map{}}  //导出工作的映射表(任务 -> 结果)
var GitLabIssueMap *CachesMap = &CachesMap{cache: &sync.Map{}} // GitLab Issue和Task Id的映射表(任务 -> GitLab Issue)

type ExportResult struct {
	Done     chan struct{}
	FilePath string
	Error    error
}

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

type cleanTask struct {
	Type int // 清理类型(0 and 1)
	ID   string
}

type QueryTask struct {
	ID        string
	DBName    string
	Action    string // 表示SQL执行的DML
	Statement string
	Env       string // 所执行环境
	Service   string
	deadline  int // 单个SQL的超时时间（单位为秒）
	// UserID    uint // 关联执行用户id
}
type QTaskGroup struct {
	GID      string
	DML      string
	QTasks   []*QueryTask
	deadline int  //整个任务组的超时时间
	UserId   uint // repeat
}

// 封装QueryTask 结合GitLab Issue
type IssueQTask struct {
	QTG    *QTaskGroup
	QIssue *Issue
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
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(qtg.deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
	defer cancel()

	ep := GetEventProducer()
	rg := &SQLResultGroup{
		GID:      qtg.GID,
		resGroup: make([]*SQLResult, 0),
	}
	for _, task := range qtg.QTasks {
		fmt.Println("debug>>>", task)
		var result SQLResult = SQLResult{
			ID:   task.ID,
			Stmt: task.Statement,
		}
		// if task.Action != qtg.DML {
		// 	result.errrr = GenerateError("ActionNotMatch", "DML and Action is not match")
		// 	result.ErrMsg = result.errrr.Error()
		// 	rg.resGroup = append(rg.resGroup, &result)
		// 	break
		// }
		// 获取对应数据库实例进行SQL查询
		op, err := HaveDBIst(task.Env, task.DBName, task.Service)
		if err != nil {
			result.errrr = err
			result.ErrMsg = result.errrr.Error()
			rg.resGroup = append(rg.resGroup, &result)
			break
		}
		// 执行前健康检查DB
		err = op.HealthCheck(timeoutCtx)
		if err != nil {
			result.errrr = GenerateError("HealthCheckFailed", err.Error())
			result.ErrMsg = result.errrr.Error()
			rg.resGroup = append(rg.resGroup, &result)
			break
		}
		// 拥有细粒度超时控制的核心查询函数
		if task.Action == "select" {
			result = op.Query(timeoutCtx, task.Statement, task.ID)
		} else {
			result = op.Excute(timeoutCtx, task.Statement, task.ID)
		}
		log.Printf("task group_id=%s iid=%s is completed", rg.GID, task.ID)
		rg.resGroup = append(rg.resGroup, &result)
		// 如果该条SQL遇到ERROR立即中止后续执行
		if result.errrr != nil {
			break
		}
	}
	ep.Produce(Event{
		Type:    "save_result",
		Payload: rg,
	})
}

// func CreateSQLQueryTaskWithIssue(statement, database string, userId uint, issue *Issue) *IssueQueryTask {
// 	//! context控制超时
// 	issueTask := IssueQueryTask{
// 		QTask: &QueryTask{
// 			ID:        GenerateUUIDKey(),
// 			DBName:    database,
// 			Statement: statement,
// 			deadline:  30,
// 			UserID:    userId,
// 			Env: ,
// 		},
// 		QIssue: issue,
// 	}

// 	return &issueTask
// }

func (task *QueryTask) ExcuteTask(ctx context.Context) {
	log.Printf("task id=%s is working", task.ID)
	//! 执行任务函数只当只关心任务处理逻辑本身
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(task.deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
	defer cancel()

	ep := GetEventProducer()
	// 获取对应数据库实例进行SQL查询
	op, err := HaveDBIst(task.Env, task.DBName, task.Service)
	if err != nil {
		queryResult := &SQLResult{
			ID:      task.ID,
			Results: nil,
			errrr:   err,
		}
		ep.Produce(Event{
			Type:    "save_result",
			Payload: queryResult,
		})
		return
	}
	// 执行前健康检查DB
	err = op.HealthCheck(timeoutCtx)
	if err != nil {
		queryResult := &SQLResult{
			ID:      task.ID,
			Results: nil,
			errrr:   GenerateError("HealthCheckFailed", err.Error()),
		}
		ep.Produce(Event{
			Type:    "save_result",
			Payload: queryResult,
		})
		return
	}
	// 拥有细粒度超时控制的核心查询函数
	result := op.Query(timeoutCtx, task.Statement, task.ID)
	log.Printf("task id=%s is completed", task.ID)
	ep.Produce(Event{
		Type:    "save_result",
		Payload: result,
	})

}

type ExportTask struct {
	ID       string `json:"task_id"`
	Type     string `json:"export_type"`
	FileName string
	UserID   uint
	deadline int // task timeout
	Result   *ExportResult
}

// 导出任务入队
func SubmitExportTask(id, exportType string, userId uint) *ExportTask {
	today := time.Now().Format("20060102150405")
	conf := GetAppConfig()
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
	ep := GetEventProducer()
	ep.Produce(Event{
		Type:    "export_result",
		Payload: task,
	})
	return task
}

// 导出SQL查询结果
func ExportSQLTask(ctx context.Context, task *ExportTask) error {
	var cachesMapResult *SQLResult
	if task.ID == "" {
		return GenerateError("TaskNotExist", "task id is not found")
	}
	// 检查结果集resultMap还是否存在当前task的result
	mapVal, resultExist := ResultMap.Get(task.ID)
	if !resultExist {
		// 从QueryTaskMap中找对应task id的任务信息，重新执行查询任务来获取结果
		taskMap, taskExist := QueryTaskMap.Get(task.ID)
		if !taskExist {
			return GenerateError("QueryTaskError", "query task id is not exist,please re-excute sql query")
		}
		switch t := taskMap.(type) {
		case *QueryTask:
			t.ExcuteTask(ctx)
		case *QTaskGroup:
			t.ExcuteTask(ctx)
		default:
			return GenerateError("QueryTaskError", "query task object type not match")
		}
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= task.deadline; i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(task.ID)
			if ok {
				assertVal, ok := mapVal.(*SQLResult)
				if !ok {
					return GenerateError("QueryResultError", "query result data type is incorrect")
				}
				log.Println("[Re-Excute] re-excute sql task completed")
				cachesMapResult = assertVal
				break
			}
		}
	} else {
		assertVal, ok := mapVal.(*SQLResult)
		if !ok {
			return errors.New("resultData is incorrect type")
		}
		cachesMapResult = assertVal
	}
	conf := GetAppConfig()
	switch {
	case task.Type == "csv":
		err := convertCSVFile(conf.ExportEnv.FilePath, task.FileName, cachesMapResult.Results)
		if err != nil {
			return err
		}
		time.AfterFunc(time.Second*time.Duration(conf.ExportEnv.HouseKeeping), func() {
			// HouseKeepQueue <- task
			ep := GetEventProducer()
			ep.Produce(Event{
				Type:    "file_housekeeping",
				Payload: task,
			})
		})
	default:
		log.Println("[WARN] 暂不支持其他方式导出")
		return GenerateError("TypeError", "export type is unknown")
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
		return GenerateError("ConvertError", "data length is zero")
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
