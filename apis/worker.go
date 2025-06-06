package apis

import (
	"context"
	"fmt"
	"log"
)

// 清理已读结果集队列
func StartCleanWorker(ctx context.Context) {
	fmt.Println("Map Clean Worker Starting ...")
	cleanTypeMap := map[int]*CachesMap{
		0: ResultMap,
		1: QueryTaskMap,
		2: SessionMap,
		3: ExportWorkMap,
	}
	cleanTypeInfoMap := map[int]string{
		0: "ResultMap",
		1: "QueryTaskMap",
		2: "SessionMap",
		3: "ExportWorkMap",
	}
	go func() {
		for {
			select {
			// 根据类型选择不同的清理方式(v3.0)
			case t := <-CleanQueue:
				mapOperator := cleanTypeMap[t.Type]
				mapOperator.Del(t.ID)
				log.Printf("type=%v taskID=%s Cleaned Up", cleanTypeInfoMap[t.Type], t.ID)
			case <-ctx.Done():
				log.Println("因错误退出，关闭Clean Worker. Error:", ctx.Err().Error())
				return
			}
		}
	}()
}

// File CLeaner
func StartHousekeeper(ctx context.Context) {
	fmt.Println("HouseKeeper Starting ...")
	go func() {
		for {
			select {
			case t := <-HouseKeepQueue:
				// 细粒度控制删除文件
				FileClean(t.Result.FilePath)
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
					QueryTaskMap.Set(t.ID, t, 300, 1) // 存储查询任务信息
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
					ResultMap.Set(res.ID, res, 180, 0)
				case <-ctx.Done():
					log.Println("因错误退出，关闭当前Reader, Error:", ctx.Err().Error())
					return
				}
			}
		}()
	}
}

// 结果集导出Worker
func StartResultExportor(ctx context.Context) {
	for i := 0; i < 3; i++ {
		go func() {
			for {
				select {
				case t := <-ExportQueue:
					//导出下载逻辑
					fmt.Println("start export task", t.ID)
					err := ExportSQLTask(ctx, t)
					if err != nil {
						// 添加错误信息
						t.Result.Error = err
						t.Result.FilePath += "_failed"
						t.Result.Done <- struct{}{}
						fmt.Println("export task is error", t.ID)
						continue
					}
					fmt.Println("completed export task", t.ID)
				case <-ctx.Done():
					log.Println("因错误退出，关闭当前Reader, Error:", ctx.Err().Error())
					return
				}
			}
		}()
	}
}
