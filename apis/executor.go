package apis

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"slices"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

// 业务数据库配置（从特定源读取）
type AllEnvDBConfig struct {
	Databases map[string]map[string]MySQLConfig `yaml:"databases"`
}

type MySQLConfig struct {
	MaxConn  int      `yaml:"max_conn"`
	IdleTime int      `yaml:"idle_time"`
	Name     string   `yaml:"name"`
	Host     string   `yaml:"host"`
	Password string   `yaml:"password"`
	User     string   `yaml:"user"`
	Port     string   `yaml:"port"`
	DSN      string   `yaml:"dsn"`
	Exclude  []string `yaml:"exclude"`
}

// 读取配置，加载数据库池
func LoadInDB() {
	var config AllEnvDBConfig
	// 从YAML方式读取
	Fieldata, err := os.ReadFile("config/db.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(Fieldata, &config)
	if err != nil {
		panic(err)
	}

	// 注册DB实例进入池子
	pool := newDBPoolManager()
	err = pool.register(&config)
	if err != nil {
		panic(err)
	}
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

// 多数据库连接的新实例
type DBInstance struct {
	conn *sql.DB
	name string // 数据库名称
}

// 数据库连接的池子
type DBPoolManager struct {
	Pool map[string]map[string]*DBInstance
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

// 以原生SELECT SQL语句执行查询
func (instance *DBInstance) QueryForRaw(ctx context.Context, statement string) (*sql.Rows, error) {
	return instance.conn.QueryContext(ctx, statement)
}

// 以原生DML SQL进行执行（无参数注入）
func (instance *DBInstance) ExcuteForRaw(ctx context.Context, statement string) (int64, int64, error) {
	stmt, err := instance.conn.Prepare(statement)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		return 0, 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	return lastId, rows, nil
}

func (instance *DBInstance) TransferExcuteRaw(ctx context.Context, statement string) (int64, int64, error) {
	tx, err := instance.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if recoverErr := recover(); recoverErr != nil {
			ErrorPrint("TransferExcute", "Transfer Excute Error")
			tx.Rollback()
		}
	}()
	lastId, rows, err := instance.ExcuteForRaw(ctx, statement)
	if err != nil {
		panic(err)
	}
	if err := tx.Commit(); err != nil {
		panic(GenerateError("TransferExcute", "Your Transfer Excute Error: "+err.Error()))
	}
	return lastId, rows, nil
}

// 对内暴露的查询SQL接口
func (instance *DBInstance) Query(ctx context.Context, sqlRaw string, taskId string) *QueryResult {
	errCh := make(chan error, 1)

	queryResult := &QueryResult{
		QueryRaw: sqlRaw,
		ID:       taskId,
	}

	// 异步执行查询SQL
	go func() {
		start := time.Now()
		rows, err := instance.QueryForRaw(ctx, sqlRaw)
		if err != nil {
			errCh <- err
			return
		}
		defer rows.Close()
		end := time.Since(start)
		queryResult.QueryTime = end.Seconds()

		start = time.Now()
		//! 结果集处理
		// 获取SQL要查询的列名
		cols, _ := rows.Columns()
		// 遍历结果集，逐行处理结果
		for rows.Next() {
			if rows.Err() != nil {
				log.Println("该行有问题，直接跳过")
				break
			}
			values := make([]any, len(cols)) // 每一行都创建结果集容器的切片,按照列的顺序进行存储

			// 初始化结果集容器；将该切片中的元素都初始化为sql.RawBytes容器，用于存放列值
			for i := range values {
				values[i] = new(sql.RawBytes) // 原始SQL语句最终以字节切片的方式进行存储；type RawBytes []byte
			}
			// 获取结果集，填充进来
			if err := rows.Scan(values...); err != nil {
				errCh <- GenerateError("TaskResult Handle Error", err.Error())
				return
			}
			rowResultMap := make(map[string]any, 0) // 创建存储每行数据结果的容器（Map）
			for i, colName := range cols {
				// 列名切片顺序和values顺序一致，断言结果类型，然后进行存储
				if value, ok := values[i].(*sql.RawBytes); ok {
					//! 数据处理（数据脱敏，过滤等）
					rowResultMap[colName] = DataMaskHandle(colName, value)
				}
			}
			queryResult.Results = append(queryResult.Results, rowResultMap)
			queryResult.RowCount = len(queryResult.Results)
		}
		end = time.Since(start)
		queryResult.HandleTime = end.Seconds()
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		queryResult.Error = GenerateError("Task TimeOut", "query sql task is failed ,query timeout")
		return queryResult
	case err := <-errCh:
		if err != nil {
			queryResult.Error = err
		}
		return queryResult
	}
	// 最终要返回的结果是[]map[string]any,也就是说切片里每个元素都是一行数据
}

func (instance *DBInstance) Healthz(ctx context.Context) error {
	return instance.conn.PingContext(ctx)
}

// the validate func is discard（1.0）
// func (instance *DBInstance) validateCheck(statement string) (string, error) {
// 	// 目前只支持一条SQL的查询，多余的直接丢弃
// 	sqls := strings.Split(statement, ";")
// 	sqlCount := len(sqls)
// 	// sql语句数错误处理(目前只支持单SQL查询)
// 	if sqlCount != 2 || !strings.HasSuffix(statement, ";") {
// 		if sqlCount == 0 {
// 			return "", GenerateError("SQL Validate Check", "validate check failed, synatx or format problem, no sql match")
// 		} else if sqlCount > 1 {
// 			// 提示出现的多余SQL语句
// 			// 因为split分割出来最低是1，即无论是否找到分隔符都是1
// 			for _, v := range sqls[1:] {
// 				log.Printf("<...> Others SQL %s\n", v)
// 			}
// 			return "", GenerateError("SQL Validate Check", "only 1 SQL `SELECT` query is suppoerted")
// 		}
// 	}
// 	statement = sqls[0] + ";"

// 	// 除SELECT外语句都不支持
// 	illegalSQL := []string{"UPDATE", "DELETE", "DROP", "INSERT", "CREATE", "ALTER"}
// 	for _, illegal := range illegalSQL {
// 		if strings.Contains(strings.ToUpper(statement), illegal) {
// 			return "", GenerateError("SQL Validate Check", "illegal operations exist in sql statement")
// 		}
// 	}

// 	return statement, nil
// }

// 初始化数据库池管理者（全局一次）
func newDBPoolManager() *DBPoolManager {
	once.Do(func() {
		globalDBPool = &DBPoolManager{
			Pool: make(map[string]map[string]*DBInstance),
		}
	})
	return globalDBPool
}

// 打开数据库实例连接
func newDBInstance(usr, pwd, host, port string, maxConn, idleTime int) (*DBInstance, error) {
	// e.g: zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql", usr, pwd, host, port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxIdleTime(time.Duration(idleTime) * time.Second)
	db.SetMaxOpenConns(maxConn)
	db.SetMaxIdleConns(maxConn)
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return &DBInstance{
		conn: db,
	}, nil
}

// 解析配置并注册
func (manager *DBPoolManager) register(configData *AllEnvDBConfig) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for env, dbList := range configData.Databases {
		for istName, dbConf := range dbList {
			db, err := newDBInstance(dbConf.User, dbConf.Password, dbConf.Host, dbConf.Port, dbConf.MaxConn, dbConf.IdleTime)
			if err != nil {
				ErrorPrint("DBRegisterError", "database register is failed, "+err.Error())
				continue
			}
			if manager.Pool[env] == nil {
				manager.Pool[env] = make(map[string]*DBInstance)
			}
			db.name = istName
			manager.Pool[env][istName] = db
		}
	}
	return nil
}

// 关闭数据库实例池
func (manager *DBPoolManager) CloseDBPool() {
	// manager := newDBPoolManager()
	for env, istList := range manager.Pool {
		for _, ist := range istList {
			err := ist.conn.Close()
			if err != nil {
				ErrorPrint("CloseDBError", fmt.Sprintf("[%s] close db %s connection is failed, %s", env, ist.name, err.Error()))
			}
		}

	}
}

// 获取指定环境下所有db实例
func (manager *DBPoolManager) getDBList(env string) []string {
	istNameList := []string{}
	for istName, _ := range manager.Pool[env] {
		// istNameList = append(istNameList, dbIst.name)
		istNameList = append(istNameList, istName)
	}
	// 新增排序功能
	slices.Sort(istNameList)
	return istNameList
}

// 获取指定db实例
func HaveDBIst(env, name, service string) (*DBInstance, error) {
	globalDBPool.mu.RLock()
	defer globalDBPool.mu.RUnlock()
	if name == "" {
		return nil, GenerateError("InstanceIsNull", "db instance name is null")
	} else if env == "" {
		return nil, GenerateError("InstanceIsNull", "env name is null")
	}
	if dbIstMap, ok := globalDBPool.Pool[env]; ok {
		if dbIst, ok := dbIstMap[service]; ok {
			return dbIst, nil
		}
		return nil, GenerateError("InstanceError", fmt.Sprintf("<%s> db instance is not exist", service))
	}
	return nil, GenerateError("InstanceError", fmt.Sprintf("<%s> env is not exist", env))
}
