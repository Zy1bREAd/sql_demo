package services

import (
	"log"
	api "sql_demo/internal/api/dto"
	"sql_demo/internal/conf"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"testing"
)

func TestCRUD(T *testing.T) {
	conf.InitAppConfig()
	file := utils.StartFileLogging()
	defer file.Close()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)
	env := NewEnvService()
	// 创建
	// err := env.Create(api.QueryEnvDTO{
	// 	Name:    "unit_test_1",
	// 	IsWrite: true,
	// 	Tag:     []string{"u", "n"},
	// })

	// 更新
	err := env.Delete(api.QueryEnvDTO{
		Name: "ceshi_env_1441",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
