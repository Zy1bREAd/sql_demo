package services

import (
	"fmt"
	"log"
	api "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"testing"
)

// 测试获取和筛选
func TestGetOrFilter(T *testing.T) {
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)

	source := NewSourceService()
	val, err := source.Get(api.QueryDataBaseDTO{
		Name: "apiCreateSources",
	}, &common.Pagniation{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("debug print -", val)

	val, err = source.FilterKeyWord("slav", &common.Pagniation{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("debug print - 2", val)
}

func TestDelAndUpdate(T *testing.T) {
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)

	source := NewSourceService()
	// err := source.Delete(api.QueryDataBaseDTO{
	// 	Name: "apiCreateSources",
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }

	err := source.Update(api.QueryDataBaseDTO{
		UID: "5793d548-b706-4d17-a5dd-e2566afed372",
	}, api.QueryDataBaseDTO{
		Name:    "datacenter_test",
		Service: "DataCenter_1",
	})
	if err != nil {
		log.Fatal(err)
	}
}

// 测试新增
func TestCreate(T *testing.T) {
	// 开启文件日志记录
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)

	source := NewSourceService()
	err := source.Create(api.QueryDataBaseDTO{
		EnvName:      "hello",
		Name:         "apiCreateSources",
		IsWrite:      true,
		Service:      "datacenter",
		ExcludeTable: []string{"mysql", "users"},
		Connection: dbo.ConnectInfo{
			Password: "1234567",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	val, err := source.Get(api.QueryDataBaseDTO{
		Name: "apiCreateSources",
	}, &common.Pagniation{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("debug print -", val)

}
