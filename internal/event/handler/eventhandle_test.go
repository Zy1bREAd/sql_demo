package event

import (
	"context"
	"fmt"
	"log"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"testing"
	"time"
)

func TestExplain(T *testing.T) {
	dbIst, err := dbo.NewDBInstance(dbo.ConnectInfo{
		Host:     "124.220.17.5",
		User:     "sql_handler",
		Password: "kZ4wKAjTbmvqFT",
		Port:     "23366",
		TLS:      false,
		MaxConn:  10,
		IdleTime: 60,
	})
	if err != nil {
		log.Println(err.Error())
	}
	sqlRaw := `SELECT count(*) from sql_demo.audit_logs_v3 alv where id = 2 or create_at BETWEEN '2025-08-19 00:00:00' AND '2025-08-21 00:00:00';`
	res := dbIst.Explain(T.Context(), sqlRaw, utils.GenerateUUIDKey())
	if res.Errrrr != nil {
		fmt.Println("debug prin err:", res.ErrMsg)
		return
	}
	fmt.Println("debug print result::", res.Results)
	fmt.Println("")
}

func TestExplainAnalysis(T *testing.T) {
	start := time.Now()
	content := map[string]string{
		"sql": `
		select u1.id,u1.name from (select * from sql_demo.users where name LIKE 'testwenqiang_%' and email = '12221@qq.com') as u1 
		left join sql_demo.users u2 
		on u1.id = u2.id;
		`,
		"env":     "prod",
		"db":      "sql_demo",
		"service": "domain",
	}
	// 开启文件日志记录
	conf.InitAppConfig()
	// 连接本地应用的DB存储数据
	self := dbo.InitSelfDB()
	defer self.Close()
	// 初始化多数据库池子的实例
	dbo.LoadInDB(false)

	// 解析SQL
	ctx := context.Background()
	parseStmts, err := core.ParseV3(ctx, content["sql"])
	if err != nil {
		panic(err)
	}

	for _, stmt := range parseStmts {
		analysisRes, err := stmt.ExplainAnalysis(ctx, content["env"], content["db"], content["service"],
			core.AnalysisFnOpts{
				WithExplain: true,
				WithDDL:     true,
				WithSchema:  true,
				WithAi:      true,
			})
		if err != nil {
			log.Panic(err.Error())
		}
		fmt.Println("debug print - ai", analysisRes.AiAnalysis)
		fmt.Println("debug print - ddl", analysisRes.DDL)
		fmt.Println("debug print - info", analysisRes.InformationSchema)
		fmt.Println("debug print - explain", analysisRes.Explain.Results)

		for i, val := range analysisRes.Explain.Results {
			fmt.Println("index=", i, val)
		}
	}
	fmt.Println(time.Since(start))
}
