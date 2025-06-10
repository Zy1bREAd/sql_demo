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
var TaskQueue chan *QueryTask = make(chan *QueryTask, 30) // 预分配空间
var ResultQueue chan *QueryResult = make(chan *QueryResult, 30)
var CleanQueue chan cleanTask = make(chan cleanTask, 30)
var HouseKeepQueue chan *ExportTask = make(chan *ExportTask, 30)
var ExportQueue chan *ExportTask = make(chan *ExportTask, 30)
var QueryTaskMap *CachesMap = &CachesMap{cache: &sync.Map{}}  // 存储查询任务相关信息的集合（QueryTask)
var ExportWorkMap *CachesMap = &CachesMap{cache: &sync.Map{}} //导出工作的映射表(任务 -> 结果)

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
	Statement string
	deadline  int64 // 超时时间（单位为秒）,默认 30s
	UserID    uint  // 关联执行用户id
}

// 提交SQL查询任务入队
func SubmitSQLTask(statement string, database string, userId string) string {
	//! context控制超时
	task := &QueryTask{
		ID:        GenerateUUIDKey(),
		DBName:    database,
		Statement: statement,
		deadline:  12,
		UserID:    StrToUint(userId),
	}
	TaskQueue <- task
	log.Printf("task id=%s is enqueue", task.ID)
	return task.ID
}

func ExcuteSQLTask(ctx context.Context, task *QueryTask) {
	log.Printf("task id=%s is working", task.ID)
	//! 执行任务函数只当只关心任务处理逻辑本身
	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
	defer cancel()

	// 获取对应数据库实例进行SQL查询
	op, err := GetDBInstance(task.DBName)
	if err != nil {
		queryResult := &QueryResult{
			ID:      task.ID,
			Results: nil,
			Error:   err,
		}
		ResultQueue <- queryResult
		return
	}
	// 执行前健康检查DB
	err = op.HealthCheck(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("excute sql task is failed : %s", err.Error())
		queryResult := &QueryResult{
			ID:      task.ID,
			Results: nil,
			Error:   GenerateError("HealthCheck Failed", errMsg),
		}
		ResultQueue <- queryResult
		return
	}
	// 拥有细粒度超时控制的核心查询函数
	result := op.Query(ctx, task.Statement, task.ID)
	// 插入审计记录
	record := &QueryAuditLog{
		TaskID:       task.ID,
		UserID:       task.UserID,
		SQLStatement: task.Statement,
		DBName:       task.DBName,
	}
	err = NewAuditRecord(record)
	if err != nil {
		// 类似这种错误不应该影响当前application的运行，可以push到error list，然后在log中打印出来方便有需要的时候进行追踪。
		log.Println("[RecordFailed]", err)
	}
	log.Printf("task id=%s is completed", task.ID)
	//! 有必要管理sqltask的状态吗？
	ResultQueue <- result

}

type ExportTask struct {
	ID       string `json:"task_id"`
	Type     string `json:"export_type"`
	FileName string
	UserID   uint
	deadline int64 // task timeout
	Result   *ExportResult
}

// 导出任务入队
func SubmitExportTask(id, exportType string, userId uint) *ExportTask {
	today := time.Now().Format("20060102150405")
	conf := GetAppConfig()
	filename := fmt.Sprintf("%s_%s.csv", id, today)
	filePath := conf.ExportEnv.FilePath + "/" + filename

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
	ExportQueue <- task
	return task
}

// 导出SQL查询结果
func ExportSQLTask(ctx context.Context, task *ExportTask) error {
	var cachesMapResult *QueryResult
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
		task, ok := taskMap.(*QueryTask)
		if !ok {
			return GenerateError("QueryTaskError", "query task object type not match")
		}
		ExcuteSQLTask(ctx, task)
		// 同步方式每秒检测是否查询任务完成，来获取结果集
		for i := 0; i <= int(task.deadline); i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(task.ID)
			if ok {
				assertVal, ok := mapVal.(*QueryResult)
				if !ok {
					return GenerateError("QueryResultError", "query result data type is incorrect")
				}
				fmt.Println("[Re-Excute] re-excute sql task completed")
				cachesMapResult = assertVal
				break
			}
		}
	} else {
		assertVal, ok := mapVal.(*QueryResult)
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
			HouseKeepQueue <- task
		})
	default:
		fmt.Println("[WARN] 暂不支持其他方式导出")
		return GenerateError("TypeError", "export type is unknown")
	}
	// 假装导出要耗时10s
	// time.Sleep(2 * time.Second)
	// 完成后传递<导出结果>对象信息，并通过channel传递完成消息
	task.Result.Done <- struct{}{}
	now := time.Now()
	record := &QueryAuditLog{
		TaskID:     task.ID,     // 用于查询
		UserID:     task.UserID, // 用于查询
		IsExported: 1,
		ExportTime: &now,
	}
	UpdateExportAuditRecord(record)
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
			fmt.Println("[FileNotExist]", fileInfo.Name(), "is not exist")
			return
		}
		fmt.Println("[FileError]", err.Error())
		return
	}
	if fileInfo.IsDir() {
		fmt.Println("[Error]", fileInfo.Name(), "is not a file")
		return
	}
	err = os.Remove(filepath)
	if err != nil {
		fmt.Println("[RemoveFailed]", fileInfo.Name(), "remove occur a error", err.Error())
	}
	fmt.Println("[Completed]", fileInfo.Name(), "is cleaned up")
}
