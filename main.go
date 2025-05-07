package main

import (
	"context"
	"fmt"
	"runtime"
	"sql_demo/apis"
)

func main() {
	//! TODO：后期引入配置形式（如YAML、ENV等）来加载变量
	defer apis.ErrorRecover()
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
		fmt.Println("<debug> worker goroutine 退出前", runtime.NumGoroutine())
		cancel()
		// time.Sleep(1 * time.Second)
		// fmt.Println("<debug> worker goroutine 退出后", runtime.NumGoroutine())
	}()
	apis.StartTaskWorkerPool(ctx)
	apis.StartResultReader(ctx)
	apis.StartCleanWorker(ctx)
	// 初始化Gin以及路由( 从yaml file env中读取配置加载Server )
	apis.InitRouter()
}
