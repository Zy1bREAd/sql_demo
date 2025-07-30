package core

import (
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"slices"
	"sql_demo/internal/utils"
	"strconv"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

type SQLParser struct {
	Action   string // 代表DML类型
	SafeStmt string // 经过语法检验的原生SQL
}

func signelParseV2(sqlRaw string) (SQLParser, error) {
	// stmt, err := p.Parse(sqlRaw)
	// if err != nil {
	// 	return utils.GenerateError("ParseStmtError", err.Error())
	// }
	return SQLParser{}, nil
}

func ParseV2(dbName, sqlRaw string) ([]SQLParser, error) {
	parseRes := make([]SQLParser, 0)
	p, err := sqlparser.New(sqlparser.Options{
		TruncateUILen:  512,
		TruncateErrLen: 1024,
	})
	if err != nil {
		return parseRes, utils.GenerateError("NewParserError", err.Error())
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
			return parseRes, utils.GenerateError("ParseStmtError", err.Error())
		}
		parseBuf := sqlparser.NewTrackedBuffer(nil)
		stmt.Format(parseBuf)
		// 抽象成结构体
		psr := SQLParser{
			SafeStmt: parseBuf.String(),
		}
		switch s := stmt.(type) {
		case *sqlparser.Select:
			// LIMIT子句限制(1000)
			lmtBuf := sqlparser.NewTrackedBuffer(nil)
			s.GetLimit().Format(lmtBuf)
			if !validateLimit(lmtBuf.String()) {
				s.SetLimit(sqlparser.NewLimit(0, 1000))
				psr.SafeStmt = sqlparser.String(s)
			}
			// 判断是否完整的表名
			if !validateFullTableNameV2(s.GetFrom()) {
				return nil, utils.GenerateError("DBNameIsNotFound", "database name for your SQL TableExpr is not included, "+sqlparser.String(s))
			}
			// 手动设置From并且重新生成SQL语句
			// s.SetFrom(tableExprsList)
			psr.SafeStmt = sqlparser.String(s)
			psr.Action = "select"

		case *sqlparser.Update:
			// 判断是否完整的表名
			if !validateFullTableNameV2(s.GetFrom()) {
				return nil, utils.GenerateError("DBNameIsNotFound", "database name for your SQL TableExpr is not included, "+sqlparser.String(s))
			}
			// 手动设置From并且重新生成SQL语句
			// s.SetFrom(tableExprsList)
			psr.SafeStmt = sqlparser.String(s)
			psr.Action = "update"

		case *sqlparser.Insert:
			// 解析被操作的库和表
			// originalTable := s.Table.TableNameString()
			table, err := s.Table.TableName()
			if err != nil {
				return parseRes, utils.GenerateError("TableNameError", err.Error())
			}
			// 判断是否携带数据库名
			if table.Qualifier.IsEmpty() {
				return nil, utils.GenerateError("DBNameIsNotFound", "database name for your SQL TableExpr is not included, "+sqlparser.String(s))
				// 先不修改，暂时直接抛出来
				// s.Table.Expr = sqlparser.NewTableNameWithQualifier(originalTable, dbName)
				// psr.SafeStmt = sqlparser.String(s)
			}
			psr.Action = "insert"
		case *sqlparser.Delete:
			return nil, utils.GenerateError("IllegalAction", "dml=DELETE action is not allow")
		default:
			return nil, utils.GenerateError("ActionNotSupprt", "Unknown Action")
		}

		parseRes = append(parseRes, psr)
	}
	return parseRes, nil
}

// 校验LIMIT子句约束
func validateLimit(limitExprs string) bool {
	re, err := regexp.Compile(`\s+limit\s+([0-9]+$)`)
	if err != nil {
		utils.DebugPrint("RegexpError", err.Error())
		return false
	}
	limitList := re.FindStringSubmatch(limitExprs)
	// 没有设置LIMIT或者LIMIT大于1000需要设置最大LIMIT值
	if len(limitList) == 0 {
		return false
	} else {
		limitVal, err := strconv.ParseInt(limitList[1], 10, 64)
		if err != nil {
			utils.DebugPrint("StrConvIntError", err.Error())
			return false
		}
		if limitVal > 1000 {
			return false
		}
	}
	return true
}

// 递归检查是否完整表名（强制约束）
func validateFullTableNameV2(tableExprs sqlparser.TableExprs) bool {
	for _, from := range tableExprs {
		tempBuf := sqlparser.NewTrackedBuffer(nil)
		from.Format(tempBuf)
		currTableName := tempBuf.String()

		switch fr := from.(type) {
		case *sqlparser.AliasedTableExpr:
			switch subFr := fr.Expr.(type) {
			case *sqlparser.TableName:
				return !subFr.Qualifier.IsEmpty() // 终止条件2: 判断是否完整表名
			case *sqlparser.DerivedTable:
				// 子表
				switch subSelect := subFr.Select.(type) {
				case *sqlparser.Select:
					return validateFullTableNameV2(subSelect.GetFrom())
				default:
					utils.DebugPrint("UnknownSQL", "Unknown AsTableExpr sql parser,Oops")
				}
			default:
				// 终止条件1：判断字符串是否为完整的表名
				if !validateTableIsFull(currTableName) {
					return false
				}
				fmt.Println("当前FROM表名检测为完整状态，因此跳过...", tableExprs)
			}
		case *sqlparser.JoinTableExpr:
			// 左右子表
			tempList := make(sqlparser.TableExprs, 0)
			tempList = append(tempList, fr.LeftExpr)
			if !validateFullTableNameV2(tempList) {
				return false
			}
			tempList = nil
			tempList = append(tempList, fr.RightExpr)
			if !validateFullTableNameV2(tempList) {
				return false
			}
			return true
		default:
			utils.DebugPrint("UnknownSQL", "Unknown JoinTableExpr sql parser,Oops")
		}
	}
	return true
}

func validateTableIsFull(tableExprs string) bool {
	// split 和 正则表达式
	s := strings.Split(tableExprs, ".")
	if len(s) == 0 {
		return false
	}
	reg, err := regexp.Compile(`([\d\w_]+)\.([\d\w_]+)`)
	if err != nil {
		utils.DebugPrint("RegepError", err.Error())
		return false
	}
	findList := reg.FindStringSubmatch(tableExprs)
	return len(findList) != 0
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
		return "", utils.GenerateError("IllegalDML", "dml(DELTE) is not allowed")
	}
	var parse SQLParser
	stmt, err := parseWithVitess(statement)
	if err != nil {
		return "", utils.GenerateError("SQLParseError", err.Error())
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
		return utils.GenerateError("SQL Validate Failed", "Only `SELECT` sql query is supported")
	}
	// 暂时禁止?符号，疑似注入参数查询
	if slices.Contains([]byte(p.SafeStmt), 63) {
		return utils.GenerateError("SQL Validate Failed", "The carrying of question marks is temporarily prohibited")
	}

	return nil
}
