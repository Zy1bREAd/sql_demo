package main

import (
	"context"
	"runtime"
	"sql_demo/apis"
)

func main() {
	defer apis.ErrorRecover()
	// 开启文件日志记录
	file := apis.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := apis.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	apis.LoadInDB()
	defer apis.CloseDBPool()

	// 针对请求-工作-处理结果的context
	ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	defer func() {
		apis.DebugPrint("worker goroutine 退出前", runtime.NumGoroutine())
		cancel()
	}()
	// apis.StartTaskWorkerPool(ctx)
	// apis.StartResultReader(ctx)
	// apis.StartCleanWorker(ctx)
	// apis.StartResultExportor(ctx)
	// apis.StartHousekeeper(ctx)
	// 初始化Gin以及路由( 从yaml file env中读取配置加载Server )
	apis.InitEventDrive(ctx, 100)
	apis.InitRouter()
}
