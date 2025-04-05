package main

import (
	"context"
	"fmt"
	"log"
	"sql_demo/apis"
)

func main() {
	defer apis.ErrorRecover()
	//! TODO：后期引入配置形式（如YAML、ENV等）来加载变量
	dsnName := "zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix"
	apis.RegisterDriver("mysql", func() apis.SQLExecutor {
		return apis.RegisterMySQLDriver(dsnName)
	})
	op, err := apis.GetDriver("mysql")
	if err != nil {
		panic(err)
	}
	err = op.HealthCheck(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("DB Connection Health is OK!")

	re, err := op.Query("UPDATE zabbix.actions set status = 3 WHERE actionid = 6;")
	if err != nil {
		panic(err)
	}
	fmt.Println(re)
	defer op.Close()
}
