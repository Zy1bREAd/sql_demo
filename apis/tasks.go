package apis

import (
	"context"
	"fmt"
	"log"
	"time"
)

// 维护全局变量
var TaskQueue chan *QueryTask = make(chan *QueryTask, 30) // 预分配空间
var ResultQueue chan *QueryResult = make(chan *QueryResult, 30)
var CleanQueue chan string = make(chan string, 30)

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

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
		deadline:  10,
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
	// log.Printf("<%s> DB Connection HealthCheck OK", op.name)
	result := op.Query(ctx, task.Statement, task.ID)
	// 插入审计记录
	err = NewAuditRecord(task.UserID, task.ID, task.Statement, task.DBName)
	if err != nil {
		// 类似这种错误不应该影响当前application的运行，可以push到error list，然后在log中打印出来方便有需要的时候进行追踪。
		log.Println(err)
	}
	log.Printf("task id=%s is completed", task.ID)
	//! 有必要管理sqltask的状态吗？
	ResultQueue <- result

}
