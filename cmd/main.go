package main

import (
	"context"
	"runtime"
	"sql_demo/internal"
	"sql_demo/internal/auth"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

func main() {
	// defer apis.ErrorRecover()
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB()

	// 针对请求-工作-处理结果的context
	ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	defer func() {
		utils.DebugPrint("worker goroutine 退出前", runtime.NumGoroutine())
		cancel()
	}()
	// 初始化Gin以及路由( 从yaml file env中读取配置加载Server )
	core.InitEventDrive(ctx, 100)
	auth.InitOAuth2()
	internal.InitRouter()
}
