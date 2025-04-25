package main

import (
	"context"
	"sql_demo/apis"
)

func main() {
	defer apis.ErrorRecover()
	// 连接本地应用的DB存储数据
	// demoDsn := "oceanwang:uxje67pbQQUP@tcp(localhost:23366)/sql_demo?charset=utf8mb4&parseTime=True&loc=Local"
	self := apis.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	apis.LoadInDB()
	// defer apis.CloseDBPool()

	// 针对请求-工作-处理结果的context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	apis.StartTaskWorkerPool(ctx)
	apis.StartResultReader(ctx)
	apis.StartCleanWorker(ctx)
	// dsnName := "zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix"
	// apis.RegisterDriver("mysql", func() apis.SQLExecutor {
	// 	return apis.RegisterMySQLDriver(dsnName)
	// })
	// 初始化Gin以及路由
	apis.InitRouter()
	//! TODO：后期引入配置形式（如YAML、ENV等）来加载变量

	// // 手动提交一个任务（模拟请求）
	// // statement := "UPDATE zabbix.actions set status = 3 WHERE actionid = 6;"
	// // statement := "SELECT * FROM zabbix.`items` WHERE name = 'Number of processed text values per second';"
	// statement := "SELECT * FROM zabbix.`items` WHERE name = 'Number of processed text values per second';"
	// apis.SubmitSQLTask(statement)
	// time.Sleep(30 * time.Second)
}
