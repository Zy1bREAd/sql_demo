package core

import dbo "sql_demo/internal/db"

// 预检任务
// type CheckTaskResult struct {
// 	GID      string // 全局标识
// 	TicketID string
// 	Stmts    []SQLForParseV2 // 预检结果
// }

type SoarCheck struct {
	Results []byte // SOAR结果集
}

type ExplainCheck struct {
	Results []dbo.SQLResult // 引入普通的SQL结果集
}

type PreCheckResult struct {
	// GID       string // 全局链路ID（TaskID）
	TicketID  string
	ParsedSQL []SQLForParseV2 // 预检结果

	Explain ExplainCheck
	Soar    SoarCheck
}

// 结果集
type SQLResultGroupV2 struct {
	GID   string
	Errrr error
	Data  []*dbo.SQLResult
}

type PreCheckResultGroup struct {
	GID   string
	Errrr error
	Data  *PreCheckResult
}
