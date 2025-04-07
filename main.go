package main

import (
	"context"
	"sql_demo/apis"
	"time"
)

func main() {
	defer apis.ErrorRecover()
	apis.StartWorkerPool(context.Background())
	apis.StartResultReader(context.Background())
	//! TODO：后期引入配置形式（如YAML、ENV等）来加载变量
	dsnName := "zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix"
	apis.RegisterDriver("mysql", func() apis.SQLExecutor {
		return apis.RegisterMySQLDriver(dsnName)
	})

	// re, err := op.Query("UPDATE zabbix.actions set status = 3 WHERE actionid = 6;")
	// if err != nil {
	// 	panic(err)
	// }

	// 手动提交一个任务（模拟请求）
	// statement := "UPDATE zabbix.actions set status = 3 WHERE actionid = 6;"
	statement := "select * from actions;"
	apis.SubmitSQLTask(context.Background(), statement)
	time.Sleep(30 * time.Second)
}
