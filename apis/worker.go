package apis

import (
	"context"
	"fmt"
	"log"
	"time"
)

// 清理已读结果集队列
func StartCleanWorker(ctx context.Context) {
	fmt.Println("HouseKeeping Worker Starting ...")
	ticker := time.NewTicker(180 * time.Second)
	// defer ticker.Stop()
	go func() {
		for {
			select {
			// 定时执行清理清理动作
			case <-ticker.C:
				ResultMap.Clean()
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
						// result有错误将暴露出来
						log.Println("Your Result is Null, ERROR:", res.Error)
						return
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
