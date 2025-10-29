package main

import (
	"context"
	"runtime"
	api "sql_demo/internal/api"
	"sql_demo/internal/auth"
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
	// 针对请求-工作-处理结果的context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		utils.DebugPrint("PrintGoroutineNumber1", runtime.NumGoroutine())
		cancel()
	}()
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	core.InitKVCache()
	defer core.CloseKVCache()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)

	// 初始化Gin以及路由
	event.InitEventDrive(ctx, 100)
	auth.InitOAuth2()
	api.InitRouter()
}
