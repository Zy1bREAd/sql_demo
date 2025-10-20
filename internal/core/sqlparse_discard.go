package core

import (
	"errors"
	"io"
	"log"
	"regexp"
	"slices"
	"sql_demo/internal/utils"
	"strconv"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

// 过去通常使用正则表达式来判断

type SQLForParse struct {
	Action   string // 代表DML类型
	Table    string
	DBName   string
	SafeStmt string // 经过语法检验的原生SQL
}

// 校验LIMIT子句约束
func (s *SQLForParse) validateLimit(limitExprs string) bool {
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

// ! 递归检查是否完整表名（强制约束）
func (s *SQLForParse) validateFullTableNameV2(tableExprs sqlparser.TableExprs) bool {
	for _, from := range tableExprs {
		tempBuf := sqlparser.NewTrackedBuffer(nil)
		from.Format(tempBuf)
		currTableName := tempBuf.String()

		switch fr := from.(type) {
		case *sqlparser.AliasedTableExpr:
			switch subFr := fr.Expr.(type) {
			case *sqlparser.TableName:
				// 终止条件2: 基础TableName类型判断是否完整表名
				if subFr.Qualifier.IsEmpty() {
					return false
				}
				s.DBName = subFr.Qualifier.String()
				s.Table = subFr.Name.String()
			case *sqlparser.DerivedTable:
				// 子表
				switch subSelect := subFr.Select.(type) {
				case *sqlparser.Select:
					return s.validateFullTableNameV2(subSelect.GetFrom())
				default:
					utils.DebugPrint("UnknownSQL", "Unknown AsTableExpr sql parser,Oops")
				}
			default:
				// 此时字符串不能再断言成sqlparser类型了，因此需要加入正则来判断是否完整。
				// 终止条件1：判断字符串是否为完整的表名
				if !s.validateTableIsFull(currTableName) {
					return false
				}
				// fmt.Println("当前FROM表名检测为完整状态，因此跳过...", tableExprs)
			}
		case *sqlparser.JoinTableExpr:
			// 左右子表
			tempList := make(sqlparser.TableExprs, 0)
			tempList = append(tempList, fr.LeftExpr)
			if !s.validateFullTableNameV2(tempList) {
				return false
			}
			tempList = nil
			tempList = append(tempList, fr.RightExpr)
			if !s.validateFullTableNameV2(tempList) {
				return false
			}
			return true
		default:
			utils.DebugPrint("UnknownSQL", "Unknown JoinTableExpr sql parser,Oops")
		}
	}
	return true
}

// 判断Table表达式是否符合完整的数据库名+表名的格式
func (s *SQLForParse) validateTableIsFull(tableExprs string) bool {
	// split 和 正则表达式
	splitRes := strings.Split(tableExprs, ".")
	if len(splitRes) == 0 {
		s.DBName = tableExprs
		return false
	}
	reg, err := regexp.Compile(`([\d\w_]+)\.([\d\w_]+)`)
	if err != nil {
		utils.DebugPrint("RegepError", err.Error())
		return false
	}
	findList := reg.FindStringSubmatch(tableExprs)
	// 等于0相当于确认该Table表达式不是完整的
	resLen := len(findList)
	if resLen != 0 {
		if resLen == 3 {
			s.DBName = findList[1]
			s.Table = findList[2]
		}
		return true
	}
	return false

}

// 解析一个SQL语句（仅能通过select查询语句）
func parseWithVitess(statement string) (string, error) {
	// 为原生SQL语句创建token流
	token := sqlparser.NewTestParser().NewStringTokenizer(statement)
	// 解析单条SQL语句（如果有多条SQL需要逐个解析处理）
	stmt, err := sqlparser.ParseNext(token)
	if err != nil {
		if err == io.EOF {
			return "", errors.New("SQLForParse Statement is Null")
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
	var parse SQLForParse
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

func (p *SQLForParse) validate() error {
	// 不允许SELECT除外的操作
	p.Action = strings.Split(p.SafeStmt, " ")[0]
	lowerStr := strings.ToLower(p.Action)
	if lowerStr != "select" {
		return utils.GenerateError("SQLForParse Validate Failed", "Only `SELECT` sql query is supported")
	}
	// 暂时禁止?符号，疑似注入参数查询
	if slices.Contains([]byte(p.SafeStmt), 63) {
		return utils.GenerateError("SQLForParse Validate Failed", "The carrying of question marks is temporarily prohibited")
	}

	return nil
}
