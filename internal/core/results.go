package core

import (
	dbo "sql_demo/internal/db"
)

// 预检相关结构体
type SoarCheck struct {
	Results []byte // SOAR结果集
}

type ExplainCheck struct {
	Results []dbo.SQLResult // 引入普通的SQL结果集
}

type PreCheckResult struct {
	ParsedSQL       []SQLForParseV2 // 预检结果
	ExplainAnalysis []ExplainAnalysisResult
	Soar            SoarCheck
}

// 结果集
type SQLResultGroupV2 struct {
	Data     []*dbo.SQLResult
	Errrr    error
	GID      string
	TicketID int64 `json:"-"`
}

type PreCheckResultGroup struct {
	Data          *PreCheckResult
	Errrr         error `json:"-"`
	ErrMsg        string
	GID           string
	TicketID      int64 `json:"-"`
	IsDoubleCheck bool  `json:"-"` // 首次或第二次检查
	IsReDone      bool  `json:"-"` // 表示是否重做
}
