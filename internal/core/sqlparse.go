package core

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sql_demo/internal/clients"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"strconv"

	"vitess.io/vitess/go/vt/sqlparser"
)

type SQLForParseV2 struct {
	Action   string // 代表DML类型
	SafeStmt string // 经过语法检验的原生SQL
	RawStmt  string // 原生SQL语句
	// WhereExpr  string
	HavingExpr string
	Order      []string
	Limit      LimitParse
	Cols       []ColParse
	ColVals    []ColValsParse
	From       []FromParse
	Where      WhereParse
	Union      UnionParse
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
	Left      *WhereParse
	Right     *WhereParse
	From, To  *WhereParse
	Expr      string // 表示当前Where的整个表达式字符串
	Op        string
	SubSelect *SQLForParseV2 // 当有出现subQuery才会存储该数据
	IsSimple  bool           // 是否为最简的Where表达式
}

type UnionParse struct {
	Left  *SQLForParseV2
	Right *SQLForParseV2
}

// 对EXPLAIN执行计划的解析与建议
type ExplainAnalysisResult struct {
	DDL               []dbo.SQLResult
	InformationSchema []dbo.SQLResult
	Explain           dbo.SQLResult
	AiAnalysis        string
	TaskID            string
}

// 选项式灵活启动需要分析的函数
type AnalysisFnOpts struct {
	WithExplain bool
	WithDDL     bool
	WithSchema  bool
	WithAi      bool
}

// ! 解析拆解SQL语句为结构体
func ParseV3(ctx context.Context, sqlRaw string) ([]SQLForParseV2, error) {
	stmtList, err := parseSQLs(sqlRaw)
	if err != nil {
		return nil, err
	}
	buf := sqlparser.NewTrackedBuffer(nil)
	result := make([]SQLForParseV2, 0)
	// 抽象成结构体
	for _, stmt := range stmtList {
		// goroutine 资源控制
		if !common.CheckCtx(ctx) {
			return nil, utils.GenerateError("GoroutineError", "Goroutine Break Off")
		}

		sqlfp, err := parseStmt(stmt)
		if err != nil {
			return nil, err
		}
		stmt.Format(buf)
		sqlfp.SafeStmt = buf.String()
		sqlfp.RawStmt = buf.String()
		buf.Reset()

		// TODO: 自定义规则预检

		result = append(result, sqlfp)
	}
	return result, nil
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

// ! 核心函数：递归解析该Stmt的SQLNode节点
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
		// Where
		whereExpr := s.GetWherePredicate()
		if whereExpr != nil {
			// ! 扩展：将Where中的Expr实现深层解析
			where, err := sql.parseSQLWhere(whereExpr)
			if err != nil {
				return SQLForParseV2{}, err
			}
			sql.Where = where
		}
		// Having
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
		whereExpr := s.GetWherePredicate()
		if whereExpr != nil {
			// where.Format(buf)
			// sql.WhereExpr = buf.String()
			// buf.Reset()
			where, err := sql.parseSQLWhere(whereExpr)
			if err != nil {
				return SQLForParseV2{}, err
			}
			sql.Where = where
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
	// EXPLAIN 执行计划
	case *sqlparser.ExplainStmt:
		sql.Action = "explain"
		return parseStmt(s.Statement)
	case *sqlparser.Union:
		unionVal := UnionParse{
			Left:  &SQLForParseV2{},
			Right: &SQLForParseV2{},
		}
		sql.Action = "union"
		left, err := parseStmt(s.Left)
		if err != nil {
			return SQLForParseV2{}, utils.GenerateError("UnionError", "Union Left Parsed is Failed "+err.Error())
		}
		unionVal.Left = &left
		right, err := parseStmt(s.Right)
		if err != nil {
			return SQLForParseV2{}, utils.GenerateError("UnionError", "Union Right Parsed is Failed "+err.Error())
		}
		unionVal.Right = &right
		sql.Union = unionVal
		// sql.Union = append(sql.Union, UnionParse{
		// 	Left:  left,
		// 	Right: right,
		// })
	default:
		return SQLForParseV2{}, utils.GenerateError("UnknownSQLKind", "The SQLForParse Kind is Unknown")
	}
	return sql, nil
}

// 解析Select语句中的Cols列名
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

// 解析FROM语句
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
				// 递归
				switch subSelect := sub.Select.(type) {
				case *sqlparser.Select:
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

// 解析要Insert的值
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

func (w *WhereParse) IsEmpty() bool {
	return w == &WhereParse{}
}

// Where 部分Expr解析
func (s *SQLForParseV2) parseSQLWhere(expr sqlparser.Expr) (WhereParse, error) {
	where := WhereParse{}
	// 获取原值
	buf := sqlparser.NewTrackedBuffer(nil)
	expr.Format(buf)
	where.Expr = buf.String()
	buf.Reset()

	switch w := expr.(type) {
	//! 等值作为递归结束条件
	case *sqlparser.ComparisonExpr:
		// = 0,> 2,LIKE 9,IN 7
		leftVal, err := s.parseSQLWhere(w.Left)
		if err != nil {
			return WhereParse{}, err
		}
		where.Left = &leftVal

		rightVal, err := s.parseSQLWhere(w.Right)
		if err != nil {
			return WhereParse{}, err
		}
		where.Right = &rightVal
		where.Op = w.Operator.ToString()

	case *sqlparser.OrExpr:
		fmt.Println("Where Or")
		leftVal, err := s.parseSQLWhere(w.Left)
		if err != nil {
			return WhereParse{}, err
		}
		where.Left = &leftVal

		rightVal, err := s.parseSQLWhere(w.Right)
		if err != nil {
			return WhereParse{}, err
		}
		where.Right = &rightVal
	case *sqlparser.AndExpr:
		fmt.Println("Where And")
		leftVal, err := s.parseSQLWhere(w.Left)
		if err != nil {
			return WhereParse{}, err
		}
		where.Left = &leftVal

		rightVal, err := s.parseSQLWhere(w.Right)
		if err != nil {
			return WhereParse{}, err
		}
		where.Right = &rightVal
	case *sqlparser.BetweenExpr:
		fmt.Println("Where Between", w.From, w.To)
		fmt.Println(reflect.TypeOf(w.From), reflect.TypeOf(w.To), reflect.TypeOf(w.Left))
		leftVal, err := s.parseSQLWhere(w.Left)
		if err != nil {
			return WhereParse{}, err
		}
		where.Left = &leftVal

		fromVal, err := s.parseSQLWhere(w.From)
		if err != nil {
			return WhereParse{}, err
		}
		where.From = &fromVal

		toVal, err := s.parseSQLWhere(w.To)
		if err != nil {
			return WhereParse{}, err
		}
		where.To = &toVal
	case *sqlparser.Subquery:
		// 子查询（SELECT）
		sel, err := parseStmt(w.Select)
		if err != nil {
			return WhereParse{}, err
		}
		where.SubSelect = &sel
	case *sqlparser.ExistsExpr:
		sel, err := parseStmt(w.Subquery.Select)
		if err != nil {
			return WhereParse{}, err
		}
		where.SubSelect = &sel
	case *sqlparser.ColName:
		where.Expr = w.Name.String()
		where.IsSimple = true
	case *sqlparser.Literal:
		where.Expr = w.Val
		where.IsSimple = true
	case sqlparser.ValTuple:
		buf := sqlparser.NewTrackedBuffer(nil)
		w.Format(buf)
		where.Expr = buf.String()
		buf.Reset()
	default:
		return WhereParse{}, utils.GenerateError("UnknownWhere", "暂不支持的Where类型: "+reflect.TypeOf(w).String())
	}
	return where, nil
}

// 利用表信息、DDL信息和EXPLAIN结果生成Prompt提示词
func (s *SQLForParseV2) NewExplainPrompt(tableInfo, ddl []string, explain string) string {
	// 需要处理stmt中的反引号问题
	reg, err := regexp.Compile("`")
	if err != nil {
		utils.ErrorPrint("RegexpError", err.Error())
		return ""
	}
	regExplain := reg.ReplaceAllString(explain, "")
	return fmt.Sprintf(`
你是一位资深DBA和运维专家, 这是准备要在5.6.20版本的MySQL上执行的SQL语句.

原SQL语句:
%s

你需要结合下面相关信息对原SQL语句进行解析并提供建议.

使用JSON格式展示EXPLAIN结果:
%s

相关核心表信息：
%v

相关表DDL:
%v

最后你必须遵循严谨准确、简洁、可读性的前提, 使用以下JSON格式来回答.
{
	"statement": "原SQL语句",
	"summary": "本次解析的总结概要",
	"findings": "关键发现(target、description以及impact)",
	"recommendation": "如果有,则提出建议并给出SQL修正(数组的方式)",
}
	`, s.SafeStmt, regExplain, tableInfo, ddl)
}

// EXPLAIN 解析与建议（单条SQL）
func (s *SQLForParseV2) ExplainAnalysis(ctx context.Context, envName, DBName, SrvName string, opts AnalysisFnOpts) (*ExplainAnalysisResult, error) {
	fromLength := len(s.From)
	result := &ExplainAnalysisResult{
		DDL:               make([]dbo.SQLResult, fromLength),
		InformationSchema: make([]dbo.SQLResult, fromLength),
		Explain:           dbo.SQLResult{},
	}
	// 初始化
	taskID := utils.GenerateUUIDKey()
	ddlPrompt := make([]string, fromLength)
	schemaPrompt := make([]string, fromLength)

	ist, err := dbo.HaveDBIst(envName, DBName, SrvName)
	if err != nil {
		return nil, err
	}

	// 0. EXPLAIN
	if !common.CheckCtx(ctx) {
		return nil, utils.GenerateError("GoroutineError", "收到父Ctx的退出信号")
	}
	if opts.WithExplain {
		explain := ist.Explain(ctx, s.SafeStmt, taskID)
		if explain.Errrrr != nil {
			return nil, explain.Errrrr
		}
		result.Explain = explain
		//TODO：EXPLAIN预定义规则解析
	}
	if !common.CheckCtx(ctx) {
		return nil, utils.GenerateError("GoroutineError", "收到父Ctx的退出信号")
	}

	// 1. 获取DDL
	if opts.WithDDL {
		ddl := make([]dbo.SQLResult, fromLength)
		for key, from := range s.From {
			if from.IsDerivedTable {
				continue
			}
			res := ist.ShowCreate(ctx, from.DBName, from.TableName, taskID)
			ddl[key] = res
			// ddl = append(ddl, res)
		}
		for key, t := range ddl {
			if t.Results == nil {
				continue
			}
			// ddlPrompt = append(ddlPrompt, t.OutputJSON())
			ddlPrompt[key] = t.OutputJSON()
		}
		result.DDL = ddl
	}

	// 2. 获取Information_schema表信息
	if opts.WithSchema {
		schema := make([]dbo.SQLResult, fromLength)
		for key, from := range s.From {
			if from.IsDerivedTable {
				continue
			}
			res := ist.TableInformation(ctx, from.DBName, from.TableName, taskID)
			// schema = append(schema, res)
			schema[key] = res
		}
		for key, t := range schema {
			if t.Results == nil {
				continue
			}
			schemaPrompt[key] = t.OutputJSON()
			// schemaPrompt = append(schemaPrompt, t.OutputJSON())
		}
		result.InformationSchema = schema
	}
	if !common.CheckCtx(ctx) {
		return nil, utils.GenerateError("GoroutineError", "收到父Ctx的退出信号")
	}

	if opts.WithAi {
		// 3. 拼接prompt问题
		question := s.NewExplainPrompt(schemaPrompt, ddlPrompt, result.Explain.OutputJSON())
		// 4. 提问
		client, err := clients.NewAIClient()
		if err != nil {
			return nil, err
		}

		if !common.CheckCtx(ctx) {
			return nil, utils.GenerateError("GoroutineError", "收到父Ctx的退出信号")
		}
		chat, err := client.NewChat(ctx, question)
		if err != nil {
			return nil, err
		}
		// analyize := chat.JSONResult()
		// 目前仅获取第一个Choice
		analyize := chat.Choices[0].Message.Content
		result.AiAnalysis = analyize
	}

	return result, nil
}
