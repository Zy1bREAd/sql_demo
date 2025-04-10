package apis

import (
	"context"
	"log"
	"sync"
	"time"
)

// 维护全局变量
var TaskQueue chan *QueryTask = make(chan *QueryTask, 30) // 预分配空间
var ResultQueue chan *QueryResult = make(chan *QueryResult, 30)
var ResultMap *ResultCaches = &ResultCaches{cache: &sync.Map{}}

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

type QueryTask struct {
	ID        string
	Statement string
	Deadline  int64 // 超时时间（单位为秒）,默认 30s
}

// 提交SQL查询任务入队
func SubmitSQLTask(statement string) string {
	//! context控制超时
	task := &QueryTask{
		ID:        GenerateUUIDKey(),
		Statement: statement,
		Deadline:  10,
	}
	TaskQueue <- task
	log.Printf("task id:%s is enqueue", task.ID)
	return task.ID
}

func ExcuteSQLTask(ctx context.Context, task *QueryTask) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	// 只关注执行任务的逻辑本身
	// 应该复用连接
	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.Deadline)*time.Second)
	defer cancel()

	op, err := GetDriver("mysql")
	if err != nil {
		panic(err)
	}
	err = op.HealthCheck(ctx)
	// health check error handle
	if err != nil {
		panic(GenerateError("HealthCheck Failed", "sql task or db health check is timeout."))
	}
	log.Println("DB Connection Health is OK!")
	result := op.Query(ctx, task.Statement, task.ID)
	if result.Error != nil {
		panic(result.Error)
	}
	//! 有必要管理sqltask的状态吗？
	ResultQueue <- result
	defer op.Close()
}
