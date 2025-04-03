package apis

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// 数据库连接部分
type QueryService struct {
	DB *sql.DB
}

type QueryResult struct {
	Results   []map[string]any // 结果集列表
	QueryRaw  string           // 查询的原生SQL
	RowCount  int              // 返回结果条数
	QueryTime float64          // 查询花费的时间
}

func NewDBEngine(driverName string, dsnName string) (*QueryService, error) {
	db, err := sql.Open(driverName, dsnName)
	if err != nil {
		return nil, err
	}
	// db conncetion setting
	db.SetConnMaxIdleTime(time.Minute * 3)
	db.SetMaxOpenConns(250)
	db.SetMaxIdleConns(100)
	return &QueryService{
		DB: db,
	}, nil
}

func (q *QueryService) QueryForRaw(sqlRaw string) (*QueryResult, error) {
	// 校验SQL合法性...
	queryResult := &QueryResult{
		QueryRaw: sqlRaw,
	}
	// 通过传入原生SQL语句进行查询（后期抽出来）
	queryStart := time.Now()
	rows, err := q.DB.Query(sqlRaw)
	if err != nil {
		log.Println("SQL query error :", err)
		return nil, err
	}
	defer rows.Close()
	queryEnd := time.Since(queryStart)
	queryResult.QueryTime = queryEnd.Seconds()

	// 获取SQL要查询的列名
	cols, _ := rows.Columns()
	fmt.Println("column: ", cols)

	// 遍历结果集，逐行处理结果
	for rows.Next() {
		values := make([]any, len(cols)) // 每一行都创建结果集容器的切片,按照列的顺序进行存储

		// 初始化结果集容器；将该切片中的元素都初始化为sql.RawBytes容器，用于存放列值
		for i := range values {
			values[i] = new(sql.RawBytes) // 原始SQL语句最终以字节切片的方式进行存储；type RawBytes []byte
		}
		// 获取结果集，填充进来
		if err := rows.Scan(values...); err != nil {
			return nil, err
		}

		rowResultMap := make(map[string]any, 0) // 创建每行结果的Map
		for i, colName := range cols {
			// 列名切片顺序和values顺序一致，断言结果类型，然后进行存储
			if value, ok := values[i].(*sql.RawBytes); ok {
				if value != nil {
					// 输出的类型待优化... 目前只有string
					rowResultMap[colName] = string(*value)
				} else {
					rowResultMap[colName] = nil
				}
			}
		}
		queryResult.Results = append(queryResult.Results, rowResultMap)
		queryResult.RowCount = len(queryResult.Results)
	}
	// 最终要返回的结果是[]map[string]any,也就是说切片里每个元素都是一行数据
	return queryResult, nil
}

func (q *QueryService) Healthz(ctx context.Context) error {
	return q.DB.PingContext(ctx)
}

func (q *QueryService) validateCheck(sqlRaw string) (string, error) {
	// 目前只支持一条SQL的查询，多余的直接丢弃
	sqls := strings.Split(sqlRaw, ";")
	sqlCount := len(sqls)
	// sql语句数错误处理
	if sqlCount != 1 {
		if sqlCount == 0 {
			return "", GenerateError("SQLValidateCheck", "validate check failed, synatx or format problem, no sql match")
		} else if sqlCount > 1 {
			return "", GenerateError("SQLValidateCheck", "only 1 SQL `SELECT` query is suppoerted")
		}
	}
	sqlRaw = sqls[0] + ";"
	fmt.Println(sqlRaw)

	// 除SELECT外语句都不支持
	illegalSQL := []string{"UPDATE", "DELETE", "DROP", "INSERT"}
	for _, illegal := range illegalSQL {
		if strings.ContainsAny(strings.ToUpper(sqlRaw), illegal) {
			return "", GenerateError("SQLValidateCheck", "illegal operations exist in sql statement")
		}
	}

	return sqlRaw, nil
}
