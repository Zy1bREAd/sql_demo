package core

import dbo "sql_demo/internal/db"

// 预检相关结构体
type SoarCheck struct {
	Results []byte // SOAR结果集
}

type ExplainCheck struct {
	Results []dbo.SQLResult // 引入普通的SQL结果集
}

type PreCheckResult struct {
	ParsedSQL []SQLForParseV2 // 预检结果
	Explain   ExplainCheck
	Soar      SoarCheck
}

// 结果集
type SQLResultGroupV2 struct {
	GID   int64
	Errrr error
	Data  []*dbo.SQLResult
}

type PreCheckResultGroup struct {
	TicketID int64
	Errrr    error
	Data     *PreCheckResult
}
