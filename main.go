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
	sek, err := apis.NewDBEngine("mysql", dsnName)
	if err != nil {
		panic(err)
	}
	err = sek.Healthz(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("DB Connection Health is OK!")

	re, _ := sek.QueryForRaw("SELECT itemid, name FROM zabbix.items LIMIT 50")
	fmt.Println(re)
	defer sek.DB.Close()
}
