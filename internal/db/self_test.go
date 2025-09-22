package dbo

import (
	"fmt"
	"log"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/utils"
	"testing"
)

func TestEnvFind(T *testing.T) {
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	LoadInDB(false)

	// 测试开始
	env := QueryEnv{}
	// cond := &QueryEnv{
	// 	Name: "prod",
	// }
	result, err := env.Find(&QueryEnv{
		Name: "ceshi_env_1441",
	}, &common.Pagniation{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result, len(result))

}
