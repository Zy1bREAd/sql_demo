package dbo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sql_demo/internal/common"
	"sql_demo/internal/utils"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

type ConnectInfo struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
	TLS      bool   `json:"tls"`
	MaxConn  int    `json:"max_conn"`
	IdleTime int    `json:"idle_time"`
}

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
	RowCount   int     // 返回结果条数
	LastId     int64   // 用于Excute的最新ID
	QueryTime  float64 // 查询花费的时间
	HandleTime float64 // 处理结果集的时间
	ID         string  // task id
	Stmt       string  // 查询的原生SQL
	Errrrr     error
	ErrMsg     string           // 错误信息
	Results    []map[string]any // 结果集列表
}

// 后期转泛型
type SQLResultGroup struct {
	GID      int64
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
		envList, err := envORM.Find(&common.Pagniation{})
		if err != nil {
			panic(err)
		}
		dbList, err := dbORM.Find(&common.Pagniation{})
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
					utils.ErrorPrint("DecryptPwdErr", fmt.Sprintf("%s: %s", err.Error(), dbConf.Name))
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
				// Split至少会返回一个元素(!), 因此需要处理单个空元素的情况。
				if excludeTableList[0] == "" {
					istCfg.ExcludeTable = nil
				} else {
					istCfg.ExcludeTable = excludeTableList
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
	conn       *sql.DB
	name       string // 数据库名称
	StatusCode int
	Errrr      string
	exclude    []string
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
		res.Errrrr = utils.GenerateError("TaskTimeout", "SQL Task is failed due to timeout")
		res.ErrMsg = res.Errrrr.Error()
	case err := <-errCh:
		if err != nil {
			res.Errrrr = err
			res.ErrMsg = res.Errrrr.Error()
		}
	}
	return res
}

func (ist *DBInstance) Explain(ctx context.Context, sqlRaw string, taskId string) SQLResult {
	// 不操作脱敏加密
	return ist.Query(ctx, "EXPLAIN "+sqlRaw, taskId, nil)
}

// 查看DDL
func (ist *DBInstance) ShowCreate(ctx context.Context, dbName, tableName string, taskId string) SQLResult {
	// 不操作脱敏加密
	return ist.Query(ctx, "SHOW CREATE TABLE "+dbName+"."+tableName, taskId, nil)
}

// 查看DDL
func (ist *DBInstance) TableInformation(ctx context.Context, dbName, tableName string, taskId string) SQLResult {
	// 不操作脱敏加密
	stmt := fmt.Sprintf(`SELECT TABLE_NAME,TABLE_ROWS,
	ROUND(DATA_LENGTH/1024/1024, 2) AS DATA_SIZE_MB,
	ROUND(INDEX_LENGTH/1024/1024, 2) AS INDEX_SIZE_MB,
	ROUND((DATA_LENGTH+INDEX_LENGTH)/1024/1024, 2) AS TOTAL_SIZE_MB,
	ROUND(DATA_FREE/1024/1024, 2) AS FREE_SIZE_MB,
	ROUND(DATA_FREE/(DATA_LENGTH+INDEX_LENGTH)*100, 2) AS FRAG_PCT 
	FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s';`, dbName, tableName)
	return ist.Query(ctx, stmt, taskId, nil)
}

// 对内暴露的查询SQL接口
func (ist *DBInstance) Query(ctx context.Context, sqlRaw, taskId string, dataMaskFunc func(col string, val *sql.RawBytes) string) SQLResult {
	errCh := make(chan error, 1)
	res := SQLResult{
		Stmt: sqlRaw,
		ID:   taskId,
	}

	// 异步执行查询SQL
	go func() {
		start := time.Now()
		if !common.CheckCtx(ctx) {
			utils.ErrorPrint("GoroutineError", "收到父Ctx的退出信号")
			return
		}
		//! 核心查询
		rows, err := ist.queryRaw(ctx, sqlRaw)
		if err != nil {
			errCh <- err
			return
		}
		if !common.CheckCtx(ctx) {
			utils.ErrorPrint("GoroutineError", "收到父Ctx的退出信号")
			return
		}
		defer rows.Close()
		end := time.Since(start)
		res.QueryTime = end.Seconds()

		//! 结果集处理
		start = time.Now()
		// 获取SQL要查询的列名
		cols, _ := rows.Columns()
		// 遍历结果集，逐行处理结果
		for rows.Next() {
			if !common.CheckCtx(ctx) {
				utils.ErrorPrint("GoroutineError", "收到父Ctx的退出信号")
				return
			}
			if rows.Err() != nil {
				utils.ErrorPrint("RowDataErr", "该行数据有问题")
				break
			}
			// 每一行都创建结果集容器的切片,按照列的顺序进行存储
			values := make([]any, len(cols))
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
					if dataMaskFunc != nil {
						rowResultMap[colName] = dataMaskFunc(colName, value)
						continue
					}
					rowResultMap[colName] = string(*value)
				}
			}
			res.Results = append(res.Results, rowResultMap)
			res.RowCount = len(res.Results)
		}
		end = time.Since(start)
		res.HandleTime = end.Seconds()
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		res.Errrrr = utils.GenerateError("TaskTimeout", "SQL Task is failed due to timeout")
		res.ErrMsg = res.Errrrr.Error()
	case err := <-errCh:
		if err != nil {
			res.Errrrr = err
			res.ErrMsg = res.Errrrr.Error()
		}
	}
	return res
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
func NewDBInstance(conn ConnectInfo) (*DBInstance, error) {
	// e.g: zabbix:zabbix_password@tcp(124.220.17.5:23366)/zabbix
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql", conn.User, conn.Password, conn.Host, conn.Port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxIdleTime(time.Duration(conn.IdleTime) * time.Second)
	db.SetMaxOpenConns(conn.MaxConn)
	db.SetMaxIdleConns(conn.MaxConn)
	// 异步测试连通性
	dbIst := &DBInstance{
		conn:       db,
		StatusCode: common.Connecting,
	}
	go func() {
		err = db.Ping()
		if err != nil {
			utils.ErrorPrint("DBIstPingErr", dsn)
			dbIst.Errrr = err.Error()
			dbIst.StatusCode = common.ConnectFailed
			return
		}
		dbIst.StatusCode = common.Connected
	}()

	return dbIst, nil
}

// 建立并测试数据库实例连接
func TestDBIstConn(conn ConnectInfo) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql", conn.User, conn.Password, conn.Host, conn.Port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	err = db.Ping()
	if err != nil {
		utils.DebugPrint("DBPingErr", err.Error())
		return err
	}
	defer db.Close()
	return nil
}

// 解析配置并注册
func (manager *DBPoolManager) register(configData *AllEnvDBConfig) error {
	manager.exclude = make([]string, 0, 20)
	for env, dbList := range configData.Databases {
		if manager.Pool[env] == nil {
			manager.Pool[env] = make(map[string]*DBInstance, len(dbList))
		}
		for istName, dbConf := range dbList {
			db, err := NewDBInstance(ConnectInfo{
				User:     dbConf.User,
				Password: dbConf.Password,
				Host:     dbConf.Host,
				Port:     dbConf.Port,
				MaxConn:  dbConf.MaxConn,
				IdleTime: dbConf.IdleTime,
			})
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
	// 检查数据库黑名单列表(已迁移至预检阶段)
	// for _, illegal := range dp.ExcludeDBList() {
	// 	if name != illegal {
	// 		continue
	// 	}
	// 	return nil, utils.GenerateError("IllegalInstance", name+" DB Instance is illegal")
	// }
	// 获取实例
	if dbIstMap, ok := dp.Pool[env]; ok {
		if dbIst, ok := dbIstMap[service]; ok {
			return dbIst, nil
		}
		return nil, utils.GenerateError("InstanceError", fmt.Sprintf("<%s> db instance is not exist", service))
	}
	return nil, utils.GenerateError("InstanceError", fmt.Sprintf("<%s> env is not exist", env))
}

func (s *SQLResult) OutputJSON() string {
	if s.Errrrr != nil {
		return ""
	}
	val, err := json.Marshal(s.Results)
	if err != nil {
		utils.ErrorPrint("JSONMarshalError", err.Error())
		return ""
	}
	return string(val)
}
