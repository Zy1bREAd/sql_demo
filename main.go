package main

import (
	"context"
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
	defer cancel()
	apis.StartTaskWorkerPool(ctx)
	apis.StartResultReader(ctx)
	apis.StartCleanWorker(ctx)
	// 初始化Gin以及路由
	apis.InitRouter("localhost:21899")
	// q := `SELECT * FROM users WHERE username like ' OR 1=1 --';; DROP TABLE users;
	// `
	// apis.ParseSQL(q)
}
