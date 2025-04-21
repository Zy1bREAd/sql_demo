package apis

import (
	"context"
	"fmt"
	"log"
)

// 清理已读结果集队列
func StartCleanWorker(ctx context.Context) {
	fmt.Println("HouseKeeping Worker Starting ...")
	// ticker := time.NewTicker(180 * time.Second)
	// defer ticker.Stop()
	go func() {
		for {
			select {
			// 单独控制结果集的清理动作(v2.0)
			case taskId := <-CleanQueue:
				ResultMap.Del(taskId)
				log.Printf("taskID=%s 已清理", taskId)
			// 定时执行清理清理动作(v1.0)
			// case <-ticker.C:
			// 	ResultMap.Clean()
			case <-ctx.Done():
				log.Println("因错误退出，关闭Clean Worker. Error:", ctx.Err().Error())
				return
			}
		}
	}()
}

// WorkerPool
func StartTaskWorkerPool(ctx context.Context) {
	log.Println("Task Worker Starting ....")
	for i := 0; i < 3; i++ {
		go func() {
			for {
				select {
				case t := <-TaskQueue:
					ExcuteSQLTask(ctx, t)
				case <-ctx.Done():
					log.Println("因错误退出，关闭当前Task Worker, Error:", ctx.Err().Error())
					return
				}
			}
		}()
	}
}

// Resulter Inform
func StartResultReader(ctx context.Context) {
	fmt.Println("Result Reader Starting ...")
	for i := 0; i < 3; i++ {
		go func() {
			for {
				select {
				case res := <-ResultQueue:
					if res.Error != nil {
						// 展示SQL任务执行的错误，并一同写入ResultMap
						log.Printf("TaskId=%s TaskError=%s", res.ID, res.Error)
					}
					//! 后期核心处理结果集的代码逻辑块
					ResultMap.Set(res.ID, res)
				case <-ctx.Done():
					log.Println("因错误退出，关闭当前Reader, Error:", ctx.Err().Error())
					return
				}
			}
		}()
	}
}
