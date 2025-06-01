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
var ExportQueue chan *ExportTask = make(chan *ExportTask, 30)
var TaskInfoMap *CachesMap = &CachesMap{cache: &sync.Map{}} // taskMap存储任务相关信息

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

type cleanTask struct {
	ID   string
	Type int // 清理类型(0 and 1)
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
	fmt.Println("debug>> ", task)
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
	err = NewAuditRecord(task.UserID, task.ID, task.Statement, task.DBName)
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
	deadline int64 // task timeout
}

func SubmitExportTask(id, exportType string) *ExportTask {
	today := time.Now().Format("200601021504")
	filename := fmt.Sprintf("/tmp/%s_%s.csv", id, today)
	task := &ExportTask{
		ID:       id,
		Type:     exportType,
		deadline: 300,
		FileName: filename,
	}

	ExportQueue <- task
	return task
}

// 导出SQL查询结果
func ExportSQLTask(ctx context.Context, task *ExportTask) error {
	fmt.Println("export start ......", task)
	var cachesMapResult *QueryResult
	if task.ID == "" {
		return GenerateError("TaskNotExist", "task id is not found")
	}
	task.deadline = 60
	// 检查结果集resultMap还是否存在当前task的result
	mapVal, resultExist := ResultMap.Get(task.ID)
	fmt.Println("debug###", mapVal, resultExist)
	if !resultExist {
		// 从TaskInfoMap中找对应task id的任务信息，重新查询获取结果
		taskMap, taskExist := TaskInfoMap.Get(task.ID)
		if !taskExist {
			return errors.New("task ID state is ??? wtf not exist")
		}
		task, ok := taskMap.(*QueryTask)
		if !ok {
			return errors.New("task type is invaild")
		}
		ExcuteSQLTask(ctx, task)
		// 同步方式每秒获取新的结果集(60s内)
		for i := 0; i <= int(task.deadline); i++ {
			time.Sleep(1 * time.Second)
			mapVal, ok := ResultMap.Get(task.ID)
			if ok {
				assertVal, ok := mapVal.(*QueryResult)
				if !ok {
					return errors.New("resultData is incorrect type")
				}
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

	// convert File
	// timeoutCtx, canel := context.WithTimeout(ctx, time.Duration(task.deadline)*time.Second)
	// defer canel()

	switch {
	case task.Type == "csv":
		err := convertCSVFile(task.FileName, cachesMapResult.Results)
		if err != nil {
			return err
		}
	default:
		fmt.Println("暂不支持其他方式导出")
		return errors.New("暂不支持其他方式导出")
	}
	fmt.Println("export Done!!!!!")
	return nil

	// select {
	// case <-timeoutCtx.Done():

	// }
}

// 转换成CSV文件并存储在本地
func convertCSVFile(filename string, data []map[string]any) error {
	if len(data) <= 0 {
		return errors.New("convert failed, data length is zero")
	}
	// create csv file
	f, err := os.Create(filename)
	if err != nil {
		log.Println("convert to CSV file is Failed", err.Error())
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

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
