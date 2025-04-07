package apis

import (
	"context"
	"fmt"
	"log"
	"time"
)

var TaskQueue chan *QueryTask = make(chan *QueryTask, 30) // 预分配空间
var ResultQueue chan *QueryResult = make(chan *QueryResult, 30)

type QueryTask struct {
	ID        string
	Statement string
	Deadline  int // 超时时间（单位为秒）,默认写死30s
}

// 提交SQL查询任务入队
func SubmitSQLTask(ctx context.Context, statement string) {
	//! context控制超时
	task := &QueryTask{
		ID:        GenerateUUIDKey(),
		Statement: statement,
		Deadline:  5,
	}
	TaskQueue <- task
	log.Printf("task id:%s is enqueue", task.ID)
}

func ExcuteSQLTask(ctx context.Context, task *QueryTask) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	// 只关注执行任务的逻辑本身
	// 应该复用连接
	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.Deadline))
	defer cancel()

	op, err := GetDriver("mysql")
	if err != nil {
		panic(err)
	}
	err = op.HealthCheck(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("DB Connection Health is OK!")
	result, err := op.Query(task.Statement)
	if err != nil {
		panic(err)
	}
	// time.Sleep(10 * time.Second)
	//! 有必要管理sqltask的状态吗？
	// ResultQueue <- result
	select {
	case ResultQueue <- result:
		log.Println("Task Done")
	case <-ctx.Done():
		log.Println("SQLTask超时导致中断退出")
		ResultQueue <- &QueryResult{Error: GenerateError("Task TimeOut", "sql task is failed -> 30s timeout")}
	}
	defer op.Close()
}

// WorkerPool
func StartWorkerPool(ctx context.Context) {
	fmt.Println("worker starting....")
	for i := 0; i < 3; i++ {
		go func() {
			for {
				select {
				case t := <-TaskQueue:
					ExcuteSQLTask(ctx, t)
				case <-ctx.Done():
					log.Println("ERROR ERROR ERROR!!")
					return
				}
			}
		}()
	}
}

// Resulter Inform
func StartResultReader(ctx context.Context) {
	fmt.Println("result reader starting....")
	for i := 0; i < 3; i++ {
		go func() {
			for {
				select {
				case t := <-ResultQueue:
					if t.Error != nil {
						// result有错误将暴露出来
						log.Printf("no result.the error:%s\n", t.Error)
						return
					}
					// 获取对应task id的结果集
					fmt.Println("your result:", t)
				case <-ctx.Done():
					log.Println("ERROR ERROR ERROR!!")
					return
				}
			}
		}()
	}
}
