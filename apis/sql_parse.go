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
	action   string // 代表DML类型
	cols     []string
	from     []string
	SafeStmt string // 经过语法检验的原生SQL
}

func signelParseV2(sqlRaw string) (SQLParser, error) {
	// stmt, err := p.Parse(sqlRaw)
	// if err != nil {
	// 	return GenerateError("ParseStmtError", err.Error())
	// }
	return SQLParser{}, nil
}

func parseV2(sqlRaw string) ([]SQLParser, error) {
	parseRes := make([]SQLParser, 0)
	p, err := sqlparser.New(sqlparser.Options{
		TruncateUILen:  512,
		TruncateErrLen: 1024,
	})
	if err != nil {
		return parseRes, GenerateError("NewParserError", err.Error())
	}
	token := p.NewStringTokenizer(sqlRaw)
	// 尝试解析多条SQL语句
	for {
		stmt, err := sqlparser.ParseNext(token)
		if err != nil {
			if err == io.EOF {
				// 已读取完所有SQL语句，跳出解析SQL的Loop
				break
			}
			return parseRes, GenerateError("ParseStmtError", err.Error())
		}
		parseBuf := sqlparser.NewTrackedBuffer(nil)
		stmt.Format(parseBuf)
		fmt.Println("format = ", parseBuf.String())
		switch s := stmt.(type) {
		case *sqlparser.Select:
			colsList := make([]string, 0)
			// 解析列
			colBuf := sqlparser.NewTrackedBuffer(nil)
			for _, col := range s.GetColumns() {
				col.Format(colBuf)
				colsList = append(colsList, colBuf.String())
				colBuf.Reset()
			}
			// 解析被操作的库和表
			fromBuf := sqlparser.NewTrackedBuffer(nil)
			fromList := make([]string, 0)
			for _, v := range s.GetFrom() {
				v.Format(fromBuf)
				fromList = append(fromList, fromBuf.String())
			}
			parseRes = append(parseRes, SQLParser{
				SafeStmt: parseBuf.String(),
				from:     fromList,
				cols:     colsList,
				action:   "select",
			})
		case *sqlparser.Update:
			// 解析被操作的库和表
			fromBuf := sqlparser.NewTrackedBuffer(nil)
			fromList := make([]string, 0)
			for _, v := range s.GetFrom() {
				v.Format(fromBuf)
				fromList = append(fromList, fromBuf.String())
			}
			fmt.Println("test table = ", s.TableExprs, s.Exprs)
			vBuf := sqlparser.NewTrackedBuffer(nil)
			s.Exprs.Format(vBuf) // Exprs 是Update的列名和值
			fmt.Println("signel>>>>", vBuf)
			vBuf.Reset()
			for _, v := range s.TableExprs {
				vBuf := sqlparser.NewTrackedBuffer(nil)
				v.Format(vBuf)
				fmt.Println("Loop>>>>", vBuf)
				vBuf.Reset()
			}
			parseRes = append(parseRes, SQLParser{
				SafeStmt: parseBuf.String(),
				from:     fromList,
				action:   "update",
			})
		case *sqlparser.Insert:
			// 解析被操作的库和表
			fromBuf := sqlparser.NewTrackedBuffer(nil)
			fmt.Println(s.Columns, s.Rows, s.Table)
			s.Format(fromBuf)
			fmt.Println(">>>>>", fromBuf.String())
			parseRes = append(parseRes, SQLParser{
				SafeStmt: parseBuf.String(),
				action:   "insert",
			})
		case *sqlparser.Delete:
			return nil, GenerateError("IllegalAction", "dml=DELETE action is not allow")
		default:
			return nil, GenerateError("ActionNotSupprt", "Unknown Action")
		}
	}
	return parseRes, nil
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
	p.action = strings.Split(p.SafeStmt, " ")[0]
	lowerStr := strings.ToLower(p.action)
	if lowerStr != "select" {
		return GenerateError("SQL Validate Failed", "Only `SELECT` sql query is supported")
	}
	// 暂时禁止?符号，疑似注入参数查询
	if slices.Contains([]byte(p.SafeStmt), 63) {
		return GenerateError("SQL Validate Failed", "The carrying of question marks is temporarily prohibited")
	}

	return nil
}
