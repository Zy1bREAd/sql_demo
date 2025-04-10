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

var illegalKeys = []string{
	"privatekey", "itemid",
}

// 数据库SQL执行器（抽象层）
type SQLExecutor interface {
	// Query(string) (*sql.Rows, error)
	Query(context.Context, string, string) *QueryResult
	HealthCheck(context.Context) error
	Close() error
}

type registerFn func() SQLExecutor

// 数据库驱动注册表
var DriversMap map[string]registerFn = make(map[string]registerFn)

// 驱动注册函数
func RegisterDriver(name string, fn registerFn) {
	nameLower := strings.ToLower(name)
	DriversMap[nameLower] = fn
}

// 获取数据库驱动
func GetDriver(name string) (SQLExecutor, error) {
	nameLower := strings.ToLower(name)
	if driver, exist := DriversMap[nameLower]; exist {
		return driver(), nil
	}
	return nil, GenerateError("DriverError", fmt.Sprintf("driver %s not found", name))
}

// MySQL 数据库驱动注册
func RegisterMySQLDriver(dsnName string) *MySQLEx {
	db, err := sql.Open("mysql", dsnName)
	if err != nil {
		return nil
	}
	// db conncetion setting
	db.SetConnMaxIdleTime(time.Minute * 3)
	db.SetMaxOpenConns(250)
	db.SetMaxIdleConns(100)
	return &MySQLEx{
		DB: db,
	}
}

// SQL执行器接口的实现
type MySQLEx struct {
	// config map[string]string    // 配置中心
	DB *sql.DB
}

// 健康检查
func (ex *MySQLEx) HealthCheck(ctx context.Context) error {
	return ex.DB.PingContext(ctx)
}

// 关闭数据库连接，释放资源。
func (ex *MySQLEx) Close() error {
	return ex.DB.Close()
}

func (ex *MySQLEx) QueryForRaw(ctx context.Context, statement string) (*sql.Rows, error) {
	// 语法校验
	sqlRaw, err := ex.validateCheck(statement)
	if err != nil {
		return nil, err
	}
	// 执行SQL查询的Core Code
	return ex.DB.QueryContext(ctx, sqlRaw)
}

// 对内暴露的查询SQL接口
func (ex *MySQLEx) Query(ctx context.Context, sqlRaw string, taskId string) *QueryResult {
	// 校验SQL合法性...
	queryResult := &QueryResult{
		QueryRaw: sqlRaw,
		ID:       taskId,
	}
	// 通过传入原生SQL语句进行查询（后期抽出来）
	start := time.Now()
	rows, err := ex.QueryForRaw(ctx, sqlRaw)
	if err != nil {
		// log.Println("trace error stack:", err)
		return &QueryResult{Error: GenerateError("SQLTask Query Error", err.Error())}
	}
	defer rows.Close()
	end := time.Since(start)
	queryResult.QueryTime = end.Seconds()
	fmt.Println(queryResult)
	// 获取SQL要查询的列名
	cols, _ := rows.Columns()
	// 遍历结果集，逐行处理结果
	for rows.Next() {
		values := make([]any, len(cols)) // 每一行都创建结果集容器的切片,按照列的顺序进行存储
		// 初始化结果集容器；将该切片中的元素都初始化为sql.RawBytes容器，用于存放列值
		for i := range values {
			values[i] = new(sql.RawBytes) // 原始SQL语句最终以字节切片的方式进行存储；type RawBytes []byte
		}
		// 获取结果集，填充进来
		if err := rows.Scan(values...); err != nil {
			return &QueryResult{Error: GenerateError("TaskResult Handle Error", err.Error())}
		}

		rowResultMap := make(map[string]any, 0) // 创建存储每行数据结果的容器（Map）
		for i, colName := range cols {
			// 列名切片顺序和values顺序一致，断言结果类型，然后进行存储
			if value, ok := values[i].(*sql.RawBytes); ok {
				if value != nil {
					//! 数据处理（数据脱敏，过滤等）
					for _, key := range illegalKeys {
						if key == colName {
							rowResultMap[colName] = "******"
						} else {
							// 输出的类型待优化... 目前只支持string
							rowResultMap[colName] = string(*value)
						}

					}
				} else {
					rowResultMap[colName] = nil
				}
			}
		}
		queryResult.Results = append(queryResult.Results, rowResultMap)
		queryResult.RowCount = len(queryResult.Results)
	}
	select {
	default:
	case <-ctx.Done():
		return &QueryResult{Error: GenerateError("Task TimeOut", "sql task is failed ,timeout 10s")}
	}
	// 最终要返回的结果是[]map[string]any,也就是说切片里每个元素都是一行数据
	return queryResult
}

func (ex *MySQLEx) Healthz(ctx context.Context) error {
	return ex.DB.PingContext(ctx)
}

func (ex *MySQLEx) validateCheck(statement string) (string, error) {
	// 目前只支持一条SQL的查询，多余的直接丢弃
	sqls := strings.Split(statement, ";")
	sqlCount := len(sqls)
	fmt.Println(sqlCount, sqls)
	// sql语句数错误处理(目前只支持单SQL查询)
	if sqlCount != 2 || !strings.HasSuffix(statement, ";") {
		if sqlCount == 0 {
			return "", GenerateError("SQL Validate Check", "validate check failed, synatx or format problem, no sql match")
		} else if sqlCount > 1 {
			// 提示出现的多余SQL语句
			// 因为split分割出来最低是1，即无论是否找到分隔符都是1
			for _, v := range sqls[1:] {
				log.Printf("<...> Others SQL %s\n", v)
			}
			return "", GenerateError("SQL Validate Check", "only 1 SQL `SELECT` query is suppoerted")
		}
	}
	statement = sqls[0] + ";"
	fmt.Println(statement)

	// 除SELECT外语句都不支持
	illegalSQL := []string{"UPDATE", "DELETE", "DROP", "INSERT", "CREATE", "ALTER"}
	for _, illegal := range illegalSQL {
		if strings.Contains(strings.ToUpper(statement), illegal) {
			return "", GenerateError("SQL Validate Check", "illegal operations exist in sql statement")
		}
	}

	return statement, nil
}
