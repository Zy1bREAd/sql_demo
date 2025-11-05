package main

import (
	"context"
	"fmt"
	"runtime"
	api "sql_demo/internal/api"
	"sql_demo/internal/auth"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	event "sql_demo/internal/event/handler"
	"sql_demo/internal/utils"
)

//	@title			Swagger Example API
//	@version		1.0
//	@description	This is a sample server celler server.
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	API Support
//	@contact.url	http://www.swagger.io/support
//	@contact.email	support@swagger.io

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		124.220.17.5:21899
//	@BasePath	/api/v1

// @securityDefinitions.apikey	ApiKeyAuth
//
// @in							header
// @name						Authorization
// @externalDocs.description	OpenAPI
// @externalDocs.url			https://swagger.io/resources/open-api/
func main() {
	// 开启文件日志记录
	conf.InitAppConfig()
	core.InitManualLogger()
	defer core.CloseLogger()
	// 针对请求-工作-处理结果的context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		logger := core.GetLogger()
		logger.Info("PrintGoroutineNumber: " + string(runtime.NumGoroutine()))
		fmt.Println("PrintGoroutineNumber2", runtime.NumGoroutine())
		cancel()
	}()

	file := utils.StartFileLogging()
	defer file.Close()
	common.InitKVCache()
	defer common.CloseKVCache()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)
	auth.InitCasbin()

	// 初始化Gin以及路由
	event.InitEventDrive(ctx, 100)
	auth.InitOAuth2()
	api.InitRouter()
}
