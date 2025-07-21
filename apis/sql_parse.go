package apis

import (
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

type SQLParser struct {
	Action   string
	From     string
	DML      string
	SafeStmt string // 经过语法检验的原生SQL
}

func parseV2(sqlRaw string) ([]SQLParser, error) {
	stmtResults := make([]SQLParser, 0)
	p, err := sqlparser.New(sqlparser.Options{
		TruncateUILen:  512,
		TruncateErrLen: 1024,
	})
	if err != nil {
		return stmtResults, GenerateError("NewParserError", err.Error())
	}
	token := p.NewStringTokenizer(sqlRaw)
	// stmt, err := p.Parse(sqlRaw)
	// if err != nil {
	// 	return GenerateError("ParseStmtError", err.Error())
	// }
	// 尝试解析多条SQL语句
	for {
		stmt, err := sqlparser.ParseNext(token)
		if err != nil {
			if err == io.EOF {
				fmt.Println("读取完所有SQL")
				break
			}
			return stmtResults, GenerateError("ParseStmtError", err.Error())
		}
		parseBuf := sqlparser.NewTrackedBuffer(nil)
		stmt.Format(parseBuf)
		fmt.Println("format = ", parseBuf.String())
		switch s := stmt.(type) {
		case *sqlparser.Select:
			colBuf := sqlparser.NewTrackedBuffer(nil)
			for _, v := range s.GetColumns() {
				v.Format(colBuf)
				fmt.Println("cols=", colBuf, colBuf.String())
				colBuf.Reset()
			}
			fromBuf := sqlparser.NewTrackedBuffer(nil)
			fromList := s.GetFrom()
			for _, v := range fromList {
				v.Format(fromBuf)
				fmt.Println("from = ", fromBuf)
			}
			fmt.Println("cols number =", s.GetColumnCount())
			stmtResults = append(stmtResults, SQLParser{
				SafeStmt: parseBuf.String(),
				From:     fromBuf.String(),
				Action:   "select",
				DML:      "select",
			})
		case *sqlparser.Update:
			fmt.Println("????", "Update SQL")
		case *sqlparser.Insert:
			fmt.Println("????", "Insert SQL")
		case *sqlparser.Delete:
			fmt.Println("????", "Delete SQL")
			return nil, GenerateError("IllegalAction", "DML DELETE action is not allow")
		default:
			return nil, GenerateError("ActionNotSupprt", "Unknown Action")
		}
	}
	return stmtResults, nil
}

func selectHandle() {

}

// 解析一个SQL语句（仅能通过select查询语句）
func parseWithVitess(statement string) (string, error) {
	// 为原生SQL语句创建token流
	token := sqlparser.NewTestParser().NewStringTokenizer(statement)
	// 解析单条SQL语句（如果有多条SQL需要逐个解析处理）
	stmt, err := sqlparser.ParseNext(token)
	if err != nil {
		if err == io.EOF {
			return "", errors.New("SQL Statement is Null")
		}
		log.Println("使用Vitess解析器解析出错: ", err)
		return "", err
	}
	// 专用于select语句的解析函数，获取原生正确的SQL
	pq := sqlparser.NewParsedQuery(stmt)
	return pq.Query, nil
}

// 解析SQL语句(根据DML类型)
func ParseSQL(statement string, dml string) (string, error) {
	if strings.Contains(dml, "delete") {
		return "", GenerateError("IllegalDML", "dml(DELTE) is not allowed")
	}
	var parse SQLParser
	stmt, err := parseWithVitess(statement)
	if err != nil {
		return "", GenerateError("SQLParseError", err.Error())
	}
	parse.SafeStmt = stmt + ";"
	err = parse.validate()
	if err != nil {
		return "", err
	}

	return parse.SafeStmt, nil
}

func (p *SQLParser) validate() error {
	// 不允许SELECT除外的操作
	p.Action = strings.Split(p.SafeStmt, " ")[0]
	lowerStr := strings.ToLower(p.Action)
	if lowerStr != "select" {
		return GenerateError("SQL Validate Failed", "Only `SELECT` sql query is supported")
	}
	// 暂时禁止?符号，疑似注入参数查询
	if slices.Contains([]byte(p.SafeStmt), 63) {
		return GenerateError("SQL Validate Failed", "The carrying of question marks is temporarily prohibited")
	}

	return nil
}
