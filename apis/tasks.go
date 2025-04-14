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

// var HouseKeepingQueue chan string = make(chan string, 30) // 针对结果集读取后的housekeeping

type QueryTask struct {
	ID        string
	DBName    string
	Statement string
	Deadline  int64 // 超时时间（单位为秒）,默认 30s
}

// 提交SQL查询任务入队
func SubmitSQLTask(statement string, database string) string {
	//! context控制超时
	task := &QueryTask{
		ID:        GenerateUUIDKey(),
		DBName:    database,
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
	//! 执行任务函数只当只关心任务处理逻辑本身
	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.Deadline)*time.Second) // 针对SQL查询任务超时控制的上下文
	defer cancel()

	// 获取对应数据库实例进行SQL查询
	op, err := GetDBInstance(task.DBName)
	if err != nil {
		ResultQueue <- &QueryResult{
			Results: nil,
			Error:   err,
		}
		return
		// panic(err)
	}
	// 执行前健康检查DB
	err = op.HealthCheck(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("excute sql task is failed : %s", err.Error())
		ResultQueue <- &QueryResult{
			Results: nil,
			Error:   GenerateError("HealthCheck Failed", errMsg),
		}
		return
	}
	log.Printf("<%s> DB Connection HealthCheck OK", op.name)
	result := op.Query(ctx, task.Statement, task.ID)
	// if result.Error != nil {
	// 	ResultQueue <- &QueryResult{
	// 		Results: nil,
	// 		Error:   result.Error,
	// 	}
	// 	return
	// 	// panic(result.Error)
	// }
	//! 有必要管理sqltask的状态吗？
	ResultQueue <- result
	// defer op.Close()			引入多数据库实例连接查询，因此移除执行完SQL查询后断开连接
}
