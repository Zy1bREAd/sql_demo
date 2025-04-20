package apis

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
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

// ! 多数据库实例连接
var once sync.Once
var globalDBPool *DBPoolManager

// 数据库配置（从特定源读取）
type DataBaseConfig struct {
	DBConfig map[string]MySQLConfig `yaml:"database"`
}
type MySQLConfig struct {
	MaxConn  int    `yaml:"max_conn"`
	DSN      string `yaml:"dsn"`
	IdleTime int    `yaml:"idle_time"`
}

// 多数据库连接的新实例
type DBInstance struct {
	conn *sql.DB
	name string // 数据库名称
	// config *MySQLConfig
	// idleTime time.Time
}

type DBPoolManager struct {
	Pool map[string]*DBInstance
	mu   sync.RWMutex // 引入读写锁保证并发安全
}

// 健康检查
func (instance *DBInstance) HealthCheck(ctx context.Context) error {
	return instance.conn.PingContext(ctx)
}

// 关闭数据库连接，释放资源。
func (instance *DBInstance) Close() error {
	return instance.conn.Close()
}

func (instance *DBInstance) QueryForRaw(ctx context.Context, statement string) (*sql.Rows, error) {
	// 语法校验
	sqlRaw, err := instance.validateCheck(statement)
	if err != nil {
		return nil, err
	}
	// 执行SQL查询的Core Code
	return instance.conn.QueryContext(ctx, sqlRaw)
}

// 对内暴露的查询SQL接口
func (instance *DBInstance) Query(ctx context.Context, sqlRaw string, taskId string) *QueryResult {
	// 校验SQL合法性...
	queryResult := &QueryResult{
		QueryRaw: sqlRaw,
		ID:       taskId,
	}
	// 通过传入原生SQL语句进行查询（后期抽出来）
	start := time.Now()
	rows, err := instance.QueryForRaw(ctx, sqlRaw)
	if err != nil {
		queryResult.Error = GenerateError("SQLTask Query Error", err.Error())
		return queryResult
	}
	defer rows.Close()
	end := time.Since(start)
	queryResult.QueryTime = end.Seconds()

	//! 结果集处理
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
			queryResult.Error = GenerateError("TaskResult Handle Error", err.Error())
			return queryResult
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
		queryResult.Error = GenerateError("Task TimeOut", "sql task is failed ,timeout 10s")
		return queryResult
	}
	// 最终要返回的结果是[]map[string]any,也就是说切片里每个元素都是一行数据
	return queryResult
}

func (instance *DBInstance) Healthz(ctx context.Context) error {
	return instance.conn.PingContext(ctx)
}

func (instance *DBInstance) validateCheck(statement string) (string, error) {
	// 目前只支持一条SQL的查询，多余的直接丢弃
	sqls := strings.Split(statement, ";")
	sqlCount := len(sqls)
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

// 初始化数据库池管理者（全局一次）
func newDBPoolManager() *DBPoolManager {
	once.Do(func() {
		globalDBPool = &DBPoolManager{
			Pool: make(map[string]*DBInstance),
		}
		log.Println("Once.Do Init Pool Success, ", globalDBPool)
	})
	return globalDBPool
}

// 读取配置，加载数据库池
func LoadInDB() {
	var config DataBaseConfig
	// 从YAML方式读取
	fileData, err := os.ReadFile("config/db.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(fileData, &config)
	if err != nil {
		panic(err)
	}
	fmt.Println("yaml config: ", config)

	// 将读取到DB配置注册进数据库池子中进行管理
	pool := newDBPoolManager()
	err = pool.register(&config)
	if err != nil {
		panic(err)
	}
}

func (manager *DBPoolManager) register(configData *DataBaseConfig) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for dbName, conf := range configData.DBConfig {
		db, err := newDBInstance(dbName, conf.DSN, conf.MaxConn, conf.IdleTime)
		if err != nil {
			log.Printf("<%s> Database Register Failed,error: %s\n", dbName, err.Error())
			continue
			// return err
		}
		manager.Pool[dbName] = db
		log.Printf("<%s> DataBase Register Success", dbName)
	}
	return nil
}

// 打开数据库实例连接
func newDBInstance(name, dsn string, maxConn, idleTime int) (*DBInstance, error) {
	// e.g: zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxIdleTime(time.Minute * 3)
	db.SetMaxOpenConns(maxConn)
	db.SetMaxIdleConns(maxConn)
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return &DBInstance{
		conn: db,
		name: name,
	}, nil
}

func GetDBInstance(name string) (*DBInstance, error) {
	globalDBPool.mu.RLock()
	defer globalDBPool.mu.RUnlock()
	if instance, ok := globalDBPool.Pool[name]; ok {
		return instance, nil
	}
	return nil, GenerateError("Instance Error", fmt.Sprintf("(%s) db instance not found", name))
}
