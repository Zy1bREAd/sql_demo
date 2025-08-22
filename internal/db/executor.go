package dbo

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sql_demo/internal/conf"
	"sql_demo/internal/utils"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

// 业务数据库配置（从特定源读取）
type AllEnvDBConfig struct {
	Databases map[string]map[string]MySQLConfig `yaml:"databases"` // env -> service -> db_config
}

type MySQLConfig struct {
	MaxConn      int      `yaml:"max_conn"`
	IdleTime     int      `yaml:"idle_time"`
	TLS          bool     `yaml:"tls"`
	Name         string   `yaml:"name"`
	Host         string   `yaml:"host"`
	Password     string   `yaml:"password"`
	User         string   `yaml:"user"`
	Port         string   `yaml:"port"`
	DSN          string   `yaml:"dsn"`
	ExcludeTable []string `yaml:"exclude_table"`
	ExcludeDB    []string `yaml:"exclude_db"`
}

// type SQLError struct
// 查询和执行SQL的结果集
type SQLResult struct {
	RowCount   int // 返回结果条数
	LastId     int64
	QueryTime  float64 // 查询花费的时间
	HandleTime float64 // 处理结果集的时间
	ID         string  // task id
	Stmt       string  // 查询的原生SQL
	Errrrr     error
	ErrMsg     string           // 错误信息
	Results    []map[string]any // 结果集列表
}

type SQLResultGroup struct {
	GID      string
	ResGroup []*SQLResult
	Errrr    error
}

// 读取配置，加载数据库池
func LoadInDB(isReload bool) {
	var config AllEnvDBConfig
	readMode := "db"
	switch readMode {
	case "db":
		// 新增读取数据库加载到内存中
		var envORM QueryEnv = QueryEnv{}
		var dbORM QueryDataBase = QueryDataBase{}
		envList, err := envORM.FindAll()
		if err != nil {
			panic(err)
		}
		dbList, err := dbORM.Find()
		if err != nil {
			panic(err)
		}
		dbsConf := make(map[string]map[string]MySQLConfig, len(envList))
		for _, env := range envList {
			if dbsConf[env.Name] == nil {
				dbsConf[env.Name] = make(map[string]MySQLConfig, 1) //! 此处涉及到Map的扩容
			}
			for _, dbConf := range dbList {
				// 当EnvID匹配的时候才会加入dbsConf
				if env.ID != dbConf.EnvID {
					continue
				}

				pwd, err := utils.DecryptAES256([]byte(dbConf.Password), dbConf.Salt)
				if err != nil {
					utils.ErrorPrint("DecryptPwdErr", err.Error())
					continue
				}
				istCfg := MySQLConfig{
					MaxConn:  dbConf.MaxConn,
					IdleTime: dbConf.IdleTime,
					Name:     dbConf.Name, // 这个仅仅代表该db连接的名字
					Host:     dbConf.Host,
					Password: pwd,
					User:     dbConf.User,
					Port:     dbConf.Port,
					TLS:      dbConf.TLS,
				}
				// 处理Exclude列表(分库和表)
				excludeTableList := strings.Split(strings.TrimSuffix(dbConf.ExcludeTable, ","), ",")
				excludeDBList := strings.Split(strings.TrimSuffix(dbConf.ExcludeDB, ","), ",")
				// Split至少会返回一个元素(!)
				if excludeTableList[0] == "" {
					istCfg.ExcludeTable = nil
				} else {
					istCfg.ExcludeDB = excludeTableList
				}
				if excludeDBList[0] == "" {
					istCfg.ExcludeDB = nil
				} else {
					istCfg.ExcludeDB = excludeDBList
				}

				dbsConf[env.Name][dbConf.Service] = istCfg
			}
		}
		config.Databases = dbsConf
	case "yaml":
		// 从YAML方式读取
		Fieldata, err := os.ReadFile("config/db.yaml")
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(Fieldata, &config)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(config.Databases)
	// 注册DB实例进入池子
	err := registerPool(isReload, &config)
	if err != nil {
		panic(err)
	}
}

func registerPool(isReload bool, configData *AllEnvDBConfig) error {
	pm := GetDBPoolManager()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if isReload {
		// 热加载，因此清空原先的数据库池中配置
		pm.Pool = make(map[string]map[string]*DBInstance)
	}
	return pm.register(configData)
}

// 数据库SQL执行器（抽象层）
type SQLExecutor interface {
	Query(context.Context, string, string) *SQLResult
	Excute(context.Context, string, string) *SQLResult
	HealthCheck(context.Context) error
	Close() error
}

// ! 多数据库实例连接
var once sync.Once
var dbPool *DBPoolManager

// 多数据库连接的新实例
type DBInstance struct {
	conn    *sql.DB
	name    string // 数据库名称
	exclude []string
}

// 数据库连接的池子
type DBPoolManager struct {
	Pool    map[string]map[string]*DBInstance
	exclude []string
	mu      sync.RWMutex // 引入读写锁保证并发安全
}

// 返回表的黑名单列表
func (manager *DBPoolManager) ExcludeDBList() []string {
	return manager.exclude
}

// 返回表的黑名单列表
func (ist *DBInstance) ExcludeTableList() []string {
	return ist.exclude
}

// 健康检查
func (ist *DBInstance) HealthCheck(ctx context.Context) error {
	return ist.conn.PingContext(ctx)
}

// 关闭数据库连接，释放资源。
func (ist *DBInstance) Close() error {
	return ist.conn.Close()
}

// 以原生SQL语句执行查询(使用SELECT)
func (ist *DBInstance) queryRaw(ctx context.Context, statement string) (*sql.Rows, error) {
	return ist.conn.QueryContext(ctx, statement)
}

// 以原生DML SQL进行执行（无参数注入）
func (ist *DBInstance) excuteRaw(ctx context.Context, statement string) (int64, int64, error) {
	stmt, err := ist.conn.Prepare(statement)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	// 获取最后更新的id
	lastId, err := res.LastInsertId()
	if err != nil {
		return 0, 0, err
	}
	// 所影响的行数
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	return lastId, rows, nil
}

func (ist *DBInstance) Excute(ctx context.Context, statement, taskId string) SQLResult {
	errCh := make(chan error, 1)
	res := SQLResult{
		ID:   taskId,
		Stmt: statement,
	}

	// 超时控制
	go func() {
		start := time.Now()
		tx, err := ist.conn.BeginTx(ctx, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer func() {
			if recoverErr := recover(); recoverErr != nil {
				fmt.Println(recoverErr)
				utils.ErrorPrint("TransferExcute", "Transfer Excute Error::"+taskId)
				tx.Rollback()
				errVal, ok := recoverErr.(error)
				if !ok {
					errCh <- utils.GenerateError("RollBackError", "Unknown Error::"+taskId)
				}
				errCh <- errVal
				return
			}
		}()
		lastId, rows, err := ist.excuteRaw(ctx, statement)
		if err != nil {
			panic(err)
		}
		if err := tx.Commit(); err != nil {
			panic(utils.GenerateError("TransferExcute", "Transfer Commit Error: "+err.Error()))
		}
		end := time.Since(start)
		res.QueryTime = end.Seconds()
		res.LastId = lastId
		res.RowCount = int(rows)
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		res.Errrrr = utils.GenerateError("TaskTimeOut", "excute sql task is timeout"+taskId)
	case err := <-errCh:
		if err != nil {
			res.Errrrr = err
			res.ErrMsg = res.Errrrr.Error()
		}
	}
	return res
}

// 对内暴露的查询SQL接口
func (ist *DBInstance) Query(ctx context.Context, sqlRaw string, taskId string) SQLResult {
	errCh := make(chan error, 1)
	queryResult := SQLResult{
		Stmt: sqlRaw,
		ID:   taskId,
	}

	// 异步执行查询SQL
	go func() {
		start := time.Now()
		// 核心查询
		rows, err := ist.queryRaw(ctx, sqlRaw)
		if err != nil {
			errCh <- err
			return
		}
		defer rows.Close()
		end := time.Since(start)
		queryResult.QueryTime = end.Seconds()

		//! 结果集处理
		start = time.Now()
		// 获取SQL要查询的列名
		cols, _ := rows.Columns()
		// 遍历结果集，逐行处理结果
		for rows.Next() {
			if rows.Err() != nil {
				utils.DebugPrint("RowError", "该行数据出现问题")
				break
			}

			values := make([]any, len(cols)) // 每一行都创建结果集容器的切片,按照列的顺序进行存储
			// 初始化结果集容器；将该切片中的元素都初始化为sql.RawBytes容器，用于存放列值
			for i := range values {
				values[i] = new(sql.RawBytes) // 原始SQL语句最终以字节切片的方式进行存储；type RawBytes []byte
			}

			// 获取结果集，填充进来
			if err := rows.Scan(values...); err != nil {
				errCh <- utils.GenerateError("TaskResultError", err.Error())
				return
			}
			rowResultMap := make(map[string]any, 0) // 创建存储每行数据结果的容器（Map）
			for i, colName := range cols {
				// 列名切片顺序和values顺序一致，断言结果类型，然后进行存储
				if value, ok := values[i].(*sql.RawBytes); ok {
					//! 数据处理（数据脱敏，过滤等）
					rowResultMap[colName] = conf.DataMaskHandle(colName, value)
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
		queryResult.Errrrr = utils.GenerateError("Task TimeOut", "query sql task is failed ,query timeout")
	case err := <-errCh:
		if err != nil {
			queryResult.Errrrr = err
			queryResult.ErrMsg = queryResult.Errrrr.Error()
		}
	}
	return queryResult
	// 最终要返回的结果是[]map[string]any,也就是说切片里每个元素都是一行数据
}

// 初始化数据库池管理者（全局一次）
func GetDBPoolManager() *DBPoolManager {
	once.Do(func() {
		dbPool = &DBPoolManager{
			Pool: make(map[string]map[string]*DBInstance),
		}
	})
	return dbPool
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
		fmt.Println(dsn)
		return nil, err
	}
	return &DBInstance{
		conn: db,
	}, nil
}

// 解析配置并注册
func (manager *DBPoolManager) register(configData *AllEnvDBConfig) error {
	manager.exclude = make([]string, 0, 20)
	for env, dbList := range configData.Databases {
		if manager.Pool[env] == nil {
			manager.Pool[env] = make(map[string]*DBInstance, len(dbList))
		}
		for istName, dbConf := range dbList {
			db, err := newDBInstance(dbConf.User, dbConf.Password, dbConf.Host, dbConf.Port, dbConf.MaxConn, dbConf.IdleTime)
			if err != nil {
				utils.ErrorPrint("DBRegisterError", istName+" database register is failed, "+err.Error())
				continue
			}
			db.name = istName
			// 新增表和数据库的黑名单
			db.exclude = dbConf.ExcludeTable
			if len(dbConf.ExcludeDB) > 0 {
				manager.exclude = append(manager.exclude, dbConf.ExcludeDB...)
			}
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
				utils.ErrorPrint("CloseDBError", fmt.Sprintf("[%s] close db %s connection is failed, %s", env, ist.name, err.Error()))
			}
		}

	}
}

// 获取指定db实例
func HaveDBIst(env, name, service string) (*DBInstance, error) {
	dp := GetDBPoolManager()
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	if name == "" {
		return nil, utils.GenerateError("InstanceIsNull", "db instance name is null")
	} else if env == "" {
		return nil, utils.GenerateError("InstanceIsNull", "env name is null")
	}
	// 检查数据库黑名单列表
	for _, illegal := range dp.ExcludeDBList() {
		if name != illegal {
			continue
		}
		return nil, utils.GenerateError("IllegalInstance", name+" DB Instance is illegal")
	}
	// 获取实例
	if dbIstMap, ok := dp.Pool[env]; ok {
		if dbIst, ok := dbIstMap[service]; ok {
			return dbIst, nil
		}
		return nil, utils.GenerateError("InstanceError", fmt.Sprintf("<%s> db instance is not exist", service))
	}
	return nil, utils.GenerateError("InstanceError", fmt.Sprintf("<%s> env is not exist", env))
}
