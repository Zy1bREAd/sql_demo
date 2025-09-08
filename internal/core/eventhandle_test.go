package core

import (
	"fmt"
	"log"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"testing"
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
	// uuid := utils.GenerateUUIDKey()
	// checkEventHandler := NewCheckEventHandler()
	// checkEventHandler.Work(T.Context(), event.Event{
	// 	Type: "sql_check",
	// 	Payload: &QTaskGroupV2{
	// 		IsExport: true,
	// 		Deadline: 60,
	// 		GID:      uuid,
	// 		TicketID: uuid,
	// 		Env:      "prod",
	// 		Service:  "domain",
	// 	},
	// })
}
