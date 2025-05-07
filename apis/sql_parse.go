package apis

import (
	"log"
	"slices"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

type SQLParser struct {
	Action string
	From   string
	Stmt   string // 经过语法检验的原生SQL
}

// 解析一个SQL语句（仅能通过select查询语句）
func parseWithVitess(statement string) (string, error) {
	// 为原生SQL语句创建token流
	token := sqlparser.NewTestParser().NewStringTokenizer(statement)
	// 解析单条SQL语句（如果有多条SQL需要逐个解析处理）
	stmt, err := sqlparser.ParseNext(token)
	if err != nil {
		log.Println("使用Vitess解析器解析出错: ", err)
		return "", err
	}
	// 专用于select语句的解析函数，获取原生正确的SQL
	pq := sqlparser.NewParsedQuery(stmt)
	return pq.Query, nil
}

func ParseSQL(statement string) (string, error) {
	var parse SQLParser
	stmt, err := parseWithVitess(statement)
	if err != nil {
		return "", GenerateError("Parse Failed", err.Error())
	}
	parse.Stmt = stmt + ";"
	err = parse.validate()
	if err != nil {
		return "", err
	}

	return parse.Stmt, nil
}

func (p *SQLParser) validate() error {
	// 不允许SELECT除外的操作
	p.Action = strings.Split(p.Stmt, " ")[0]
	lowerStr := strings.ToLower(p.Action)
	if lowerStr != "select" {
		return GenerateError("SQL Validate Failed", "Only `SELECT` sql query is supported")
	}
	// 暂时禁止?符号，疑似注入参数查询
	if slices.Contains([]byte(p.Stmt), 63) {
		return GenerateError("SQL Validate Failed", "The carrying of question marks is temporarily prohibited")
	}

	return nil
}
