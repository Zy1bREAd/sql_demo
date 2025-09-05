package core

import (
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"regexp"
	"slices"
	"sql_demo/internal/utils"
	"strconv"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

type SQLForParse struct {
	Action   string // 代表DML类型
	Table    string
	DBName   string
	SafeStmt string // 经过语法检验的原生SQL
}

type SQLForParseV2 struct {
	Action     string // 代表DML类型
	SafeStmt   string // 经过语法检验的原生SQL
	WhereExpr  string
	HavingExpr string
	Order      []string
	Limit      LimitParse
	Cols       []ColParse
	ColVals    []ColValsParse
	From       []FromParse
}

// From
type FromParse struct {
	IsDerivedTable bool
	DBName         string
	TableName      string
	AsName         string
	DerivedExpr    string
	JoinOnConds    string
	SubFrom        []FromParse // 子查询的 FROM 解析结果（仅派生表需要）
}

// Cols
type ColParse struct {
	Table string
	Name  string
	As    string
}

// ColVals
type ColValsParse struct {
	Tuple []string // (2, 'Alice', 'alice@example.com')
	Expr  string   // 类似子查询的Expr
}

// Limit
type LimitParse struct {
	LimitCount int
	Offset     int
}

type WhereParse struct {
	Expr    string
	SubStmt SQLForParseV2
}

// ! 解析拆解SQL语句为结构体
func ParseV3(sqlRaw string) ([]SQLForParseV2, error) {
	stmtList, err := parseSQLs(sqlRaw)
	if err != nil {
		return nil, err
	}
	buf := sqlparser.NewTrackedBuffer(nil)
	result := make([]SQLForParseV2, 0)
	// 抽象成结构体
	for _, stmt := range stmtList {

		sqlfp, err := parseStmt(stmt)
		if err != nil {
			return nil, err
		}
		stmt.Format(buf)
		sqlfp.SafeStmt = buf.String()
		buf.Reset()

		result = append(result, sqlfp)
	}
	return result, nil
}

// 解析该Stmt的SQLNode节点
func parseStmt(stmt sqlparser.Statement) (SQLForParseV2, error) {
	sql := SQLForParseV2{}
	buf := sqlparser.NewTrackedBuffer(nil)
	switch s := stmt.(type) {
	case *sqlparser.Select:
		sql.Action = "select"
		froms, ok := sql.parseSQLFrom(s.GetFrom())
		if !ok {
			utils.ErrorPrint("ParseFROMErr", "Parse FROM is failed")
		}
		sql.From = froms
		// Where 和 Having
		where := s.GetWherePredicate()
		if where != nil {
			where.Format(buf)
			sql.WhereExpr = buf.String()
			buf.Reset()
		}
		if having := s.Having; having != nil {
			sql.HavingExpr = sqlparser.String(having.Expr)
		}

		// Order
		orders := s.GetOrderBy()
		orderVals := make([]string, 0, len(orders))
		for _, order := range orders {
			order.Format(buf)
			orderVals = append(orderVals, buf.String())
			buf.Reset()
		}
		sql.Order = orderVals

		// 列名
		cols := sql.parseSQLSelectColumns(s.GetColumns())
		sql.Cols = cols
		// Limit/Offset
		if s.GetLimit() != nil {
			limit, err := sql.parseSQLLimit(s.GetLimit())
			if err != nil {
				return SQLForParseV2{}, err
			}
			sql.Limit = limit
		}

	case *sqlparser.Update:
		sql.Action = "update"
		froms, ok := sql.parseSQLFrom(s.GetFrom())
		if !ok {
			utils.ErrorPrint("ParseFROMErr", "Parse FROM is failed")
		}
		sql.From = froms
		// Where解析
		where := s.GetWherePredicate()
		if where != nil {
			where.Format(buf)
			sql.WhereExpr = buf.String()
			buf.Reset()
		}
		// Order
		orderVals := make([]string, 0, len(s.OrderBy))
		for _, order := range s.OrderBy {
			order.Format(buf)
			orderVals = append(orderVals, buf.String())
			buf.Reset()
		}
		sql.Order = orderVals
		// Limit/Offset
		if s.Limit != nil {
			limit, err := sql.parseSQLLimit(s.Limit)
			if err != nil {
				return SQLForParseV2{}, err
			}
			sql.Limit = limit
		}

	case *sqlparser.Insert:
		sql.Action = "insert"
		table, err := s.Table.TableName()
		if err != nil {
			utils.ErrorPrint("InsertTableErr", err.Error())
			return SQLForParseV2{}, err
		}
		froms := []FromParse{{
			DBName:    table.Qualifier.String(),
			AsName:    s.Table.As.CompliantName(),
			TableName: s.Table.TableNameString(),
		},
		}
		sql.From = froms
		sql.ColVals = sql.parseSQLInsertVals(s.Rows)
	case *sqlparser.TruncateTable:
		return SQLForParseV2{}, utils.GenerateError("TruncateNotAllow", "The Truncate DML is not allow")
	case *sqlparser.Delete:
		// 不允许删除
		return SQLForParseV2{}, utils.GenerateError("DeleteNotAllow", "The Delete DML is not allow")
	default:
		return SQLForParseV2{}, utils.GenerateError("UnknownSQLErr", "The SQLForParse Type is Unknown")
	}
	return sql, nil
}

// 将原生字符串解析成Statement
func parseSQLs(stmts string) ([]sqlparser.Statement, error) {
	parseRes := make([]sqlparser.Statement, 0)
	p, err := sqlparser.New(sqlparser.Options{
		TruncateUILen:  512,
		TruncateErrLen: 1024,
	})
	if err != nil {
		return nil, utils.GenerateError("NewParserErr", err.Error())
	}

	token := p.NewStringTokenizer(stmts)
	// 尝试解析多条SQL语句
	for {
		stmt, err := sqlparser.ParseNext(token)
		if err != nil {
			// 已读取完所有SQL语句，跳出解析SQL的Loop
			if err == io.EOF {
				break
			}
			return nil, utils.GenerateError("ParseStmtErr", err.Error())
		}
		// 抽象成结构体
		parseRes = append(parseRes, stmt)
	}
	return parseRes, nil
}

func (s *SQLForParseV2) parseSQLSelectColumns(colsExpr []sqlparser.SelectExpr) []ColParse {
	colsRes := make([]ColParse, 0, len(colsExpr))
	for _, col := range colsExpr {
		switch c := col.(type) {
		case *sqlparser.StarExpr:
			colsRes = append(colsRes, ColParse{
				Name:  "*",
				Table: c.TableName.Name.String(),
			})
		case *sqlparser.AliasedExpr:
			col := ColParse{}
			if c.As.NotEmpty() {
				col.As = c.As.CompliantName()
			}
			// 获取原始col值
			switch node := c.Expr.(type) {
			case *sqlparser.ColName:
				col.Name = node.Name.String()
			case *sqlparser.Literal:
				if node.Type == sqlparser.StrVal {
					col.Name = node.Val
				}
			default:
				col.Name = sqlparser.String(c.Expr)
			}
			colsRes = append(colsRes, col)
			//! TODO：若列的Expr是SelectExpr则再次进入相对应的逻辑。
		case *sqlparser.Nextval:
			utils.ErrorPrint("NextValErr", "Dont Support Next For Value")
			buf := sqlparser.NewTrackedBuffer(nil)
			c.Format(buf)
			colsRes = append(colsRes, ColParse{
				Name: buf.String(),
			})
			buf.Reset()
		default:
			utils.ErrorPrint("UnknownColsExpr", "Unknown Col Type"+reflect.TypeOf(c).String())
		}
	}

	return colsRes
}

// 解析Select语句的FROM
func (s *SQLForParseV2) parseSQLFrom(tableExprs []sqlparser.TableExpr) ([]FromParse, bool) {
	parseList := make([]FromParse, 0, 2)
	buf := sqlparser.NewTrackedBuffer(nil)
	for _, from := range tableExprs {
		fromResult := FromParse{}
		switch f := from.(type) {
		// 别名表
		case *sqlparser.AliasedTableExpr:
			switch sub := f.Expr.(type) {
			// 普通表名
			case sqlparser.TableName:
				if !sub.Qualifier.IsEmpty() {
					fromResult.DBName = sub.Qualifier.String()
				}
				fromResult.TableName = sub.Name.String()
				fromResult.AsName = f.As.CompliantName()
				parseList = append(parseList, fromResult)
			// 派生表
			case *sqlparser.DerivedTable:
				switch subSelect := sub.Select.(type) {
				case *sqlparser.Select:
					// 递归
					fmt.Println("debug print-子查询")
					// 记录派生表（子查询）内容
					subSelect.Format(buf)
					derivedExpr := buf.String()
					buf.Reset()

					subFromRes, ok := s.parseSQLFrom(subSelect.GetFrom())
					if !ok {
						return nil, false
					}
					//! 构建当前派生表的FromParse实例（解析派生表的FROM情况）
					derivedTable := FromParse{
						AsName:         f.As.CompliantName(), // 外层别名
						DerivedExpr:    derivedExpr,
						IsDerivedTable: true,
						SubFrom:        subFromRes,
					}
					parseList = append(parseList, derivedTable)

				default:
					// 未知！
					tempBuf := sqlparser.NewTrackedBuffer(nil)
					subSelect.Format(tempBuf)
					utils.DebugPrint("UnknownSQL", "Oops:: "+tempBuf.String())
					return nil, false
				}
			default:
				utils.ErrorPrint("UnknownTableExpr", "仅支持解析普通Table和派生表")
				return nil, false
			}
		// 左右Join表
		case *sqlparser.JoinTableExpr:
			tmpJoinExprs := []sqlparser.TableExpr{
				f.LeftExpr,
				f.RightExpr,
			}
			joinFromRes, ok := s.parseSQLFrom(tmpJoinExprs)
			if !ok {
				return nil, false
			}
			for i, _ := range joinFromRes {
				f.Condition.On.Format(buf)
				joinFromRes[i].JoinOnConds = buf.String()
				buf.Reset()
			}
			parseList = append(parseList, joinFromRes...)
		case *sqlparser.ParenTableExpr:
			utils.ErrorPrint("UnknownTableExpr", f.Exprs)
			return nil, false
		default:
			utils.ErrorPrint("UnknownTableExpr", "仅支持As、Join形式")
			return nil, false
		}
	}
	return parseList, true
}

func (s *SQLForParseV2) parseSQLInsertVals(colVals sqlparser.InsertRows) []ColValsParse {
	colValsRes := make([]ColValsParse, 0)
	// 解析Insert的Cols Vals
	buf := sqlparser.NewTrackedBuffer(nil)
	switch insertCols := colVals.(type) {
	case *sqlparser.Select:
		//! 此处可扩展
		insertCols.Format(buf)
		colValsRes = append(colValsRes, ColValsParse{
			Expr: buf.String(),
		})
	case *sqlparser.Union:
		utils.ErrorPrint("UnknownSQLErr", "The Insert Col Type is Union???")
	case sqlparser.Values:
		// 使用元组的方式
		for _, ic := range insertCols {
			ic.Format(buf)
			fmt.Println("debug print -8", buf.String())
			buf.Reset()
			// 将元祖序列化成Slice
			val := make([]string, 0, len(ic))
			for _, c := range ic {
				val = append(val, sqlparser.String(c))
			}
			colValsRes = append(colValsRes, ColValsParse{
				Tuple: val,
			})
		}
	default:
		utils.ErrorPrint("UnknownSQLErr", "The Insert Col Type is Unknown")
	}
	return colValsRes
}

// 解析Limit和Offset(转换Int)
func (s *SQLForParseV2) parseSQLLimit(limit *sqlparser.Limit) (LimitParse, error) {
	buf := sqlparser.NewTrackedBuffer(nil)
	// LimitCounts
	limit.Rowcount.Format(buf)
	tmpVal := buf.String()
	limitVal, err := strconv.ParseInt(tmpVal, 10, 64)
	buf.Reset()
	if err != nil {
		return LimitParse{}, utils.GenerateError("LimitParseErr", err.Error())
	}
	// Offset
	limit.Offset.Format(buf)
	tmpVal = buf.String()
	offsetVal, err := strconv.ParseInt(tmpVal, 10, 64)
	buf.Reset()
	if err != nil {
		return LimitParse{}, utils.GenerateError("LimitParseErr", err.Error())
	}
	return LimitParse{
		LimitCount: int(limitVal),
		Offset:     int(offsetVal),
	}, nil
}

func ParseV2(dbName, sqlRaw string) ([]SQLForParse, error) {
	parseRes := make([]SQLForParse, 0)
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
		psr := SQLForParse{
			SafeStmt: parseBuf.String(),
		}
		switch s := stmt.(type) {
		case *sqlparser.Select:
			// LIMIT子句限制(1000)
			lmtBuf := sqlparser.NewTrackedBuffer(nil)
			s.GetLimit().Format(lmtBuf)
			if !psr.validateLimit(lmtBuf.String()) {
				s.SetLimit(sqlparser.NewLimit(0, 1000))
				psr.SafeStmt = sqlparser.String(s)
			}
			// 判断是否完整的表名
			if !psr.validateFullTableNameV2(s.GetFrom()) {
				errMsg := fmt.Sprintf("DB name for your SQLForParse TableExpr is not included.\n> %s\n", sqlparser.String(s))
				return nil, utils.GenerateError("DBNameIsNotFound", errMsg)
			}
			// 手动设置From并且重新生成SQL语句
			// s.SetFrom(tableExprsList)
			psr.SafeStmt = sqlparser.String(s)
			psr.Action = "select"

		case *sqlparser.Update:
			// 判断是否完整的表名
			if !psr.validateFullTableNameV2(s.GetFrom()) {
				errMsg := fmt.Sprintf("DB name for your SQLForParse TableExpr is not included.\n> %s\n", sqlparser.String(s))
				return nil, utils.GenerateError("DBNameIsNotFound", errMsg)
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
				errMsg := fmt.Sprintf("DB name for your SQLForParse TableExpr is not included.\n> %s\n", sqlparser.String(s))
				return nil, utils.GenerateError("DBNameIsNotFound", errMsg)
				// 先不修改，暂时直接抛出来
				// s.Table.Expr = sqlparser.NewTableNameWithQualifier(originalTable, dbName)
				// psr.SafeStmt = sqlparser.String(s)
			}
			psr.DBName = table.Qualifier.String()
			psr.Table = table.Name.String()
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
