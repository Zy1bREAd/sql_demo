package core

import (
	"crypto/rand"
	"slices"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"time"
)

type ConnectInfo struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
	TLS      bool   `json:"tls"`
}

type QueryDataBaseDTO struct {
	EnvID        uint        `json:"env_id"` // 关键指定EnvID
	MaxConn      int         `json:"max_conn"`
	IdleTime     int         `json:"idle_time"`
	IsWrite      bool        `json:"is_write"`
	Name         string      `json:"name"`
	UID          string      `json:"uid"`
	EnvName      string      `json:"env_name"`
	Service      string      `json:"service"`
	Desc         string      `json:"description,omitempty"`
	UpdateAt     time.Time   `json:"-"`
	ExcludeDB    []string    `json:"exclude_db"`    // 排除的数据库名
	ExcludeTable []string    `json:"exclude_table"` // 排除的数据表名
	Connection   ConnectInfo `json:"connection"`    // 连接信息
}

type QueryEnvDTO struct {
	UID     string `json:"uid"`
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Desc    string `json:"description"`
	IsWrite bool   `json:"is_write"`
}

func (env *QueryEnvDTO) toORMData() *dbo.QueryEnv {
	return &dbo.QueryEnv{
		UID:         env.UID,
		Name:        env.Name,
		Tag:         env.Tag,
		Description: env.Desc,
		IsWrite:     env.IsWrite,
	}
}

func (qdb *QueryDataBaseDTO) toORMData() *dbo.QueryDataBase {
	var excludeDBStr, excludeTableStr string
	for _, d := range qdb.ExcludeDB {
		excludeDBStr += d + ","
	}
	for _, t := range qdb.ExcludeTable {
		excludeTableStr += t + ","
	}
	var pwd string
	secretKey := make([]byte, 32)
	if qdb.Connection.Password != "" {
		// 密码加密(AES256)
		_, err := rand.Read(secretKey)
		if err != nil {
			return nil
		}
		pwd, err = utils.EncryptAES256([]byte(qdb.Connection.Password), secretKey)
		if err != nil {
			utils.DebugPrint("EncryptPWDErr", err.Error())
			return nil
		}
	}
	return &dbo.QueryDataBase{
		EnvID:        qdb.EnvID,
		UID:          qdb.UID,
		MaxConn:      qdb.MaxConn,
		IdleTime:     qdb.IdleTime,
		IsWrite:      qdb.IsWrite,
		Name:         qdb.Name,
		Service:      qdb.Service,
		Description:  qdb.Desc,
		UpdateAt:     qdb.UpdateAt,
		ExcludeDB:    excludeDBStr,
		ExcludeTable: excludeTableStr,
		Host:         qdb.Connection.Host,
		User:         qdb.Connection.User,
		Password:     pwd,
		Port:         qdb.Connection.Port,
		TLS:          qdb.Connection.TLS,
		Salt:         secretKey,
	}
}

// 热加载的封装函数
func hotReloadDBCfg(f func() error) error {
	okCh := make(chan struct{}, 1)
	defer func() {
		select {
		case <-okCh:
			utils.DebugPrint("HotReload", "hot reload config")
			dbo.LoadInDB(true) // 触发热加载配置
		default:
			// 因error没有触发热加载
		}

	}()
	err := f()
	if err != nil {
		return err
	}
	okCh <- struct{}{}
	return nil
}

func (qdb *QueryDataBaseDTO) Create() error {
	return hotReloadDBCfg(func() error {
		orm := qdb.toORMData()
		orm.UID = utils.GenerateUUIDKey()
		return orm.CreateOne()
	})
}

func (env *QueryEnvDTO) Create() error {
	return hotReloadDBCfg(func() error {
		orm := env.toORMData()
		orm.UID = utils.GenerateUUIDKey()
		return orm.CreateOne()
	})
}

// 获取指定环境下所有db实例
func (qdb *QueryDataBaseDTO) GetEnvDBList(env string) []string {
	istNameList := []string{}
	dbMgr := dbo.GetDBPoolManager()
	for istName := range dbMgr.Pool[env] {
		// istNameList = append(istNameList, dbIst.name)
		istNameList = append(istNameList, istName)
	}
	// 新增排序功能
	slices.Sort(istNameList)
	return istNameList
}

// 获取指定环境下所有db实例
func (env *QueryEnvDTO) GetEnvList() []string {
	dbMgr := dbo.GetDBPoolManager()
	envList := make([]string, 0, len(dbMgr.Pool))
	for envKey := range dbMgr.Pool {
		// istNameList = append(istNameList, dbIst.name)
		envList = append(envList, envKey)
	}
	// 新增排序功能
	slices.Sort(envList)
	return envList
}

func AllEnvInfo() map[string][]string {
	temp := make(map[string][]string, 10)
	env := QueryEnvDTO{}
	qdb := QueryDataBaseDTO{}
	envResult := env.GetEnvList()
	utils.DebugPrint("envListResult", envResult)
	for _, e := range envResult {
		dbsResult := qdb.GetEnvDBList(e)
		if dbsResult == nil {
			utils.DebugPrint("dbListisNull", "is null")
		}
		temp[e] = dbsResult
	}
	return temp
}

func (env *QueryEnvDTO) UpdateEnvInfo() error {
	return hotReloadDBCfg(func() error {
		updateData := env.toORMData()
		tmpEnv := dbo.QueryEnv{UID: env.UID}
		return tmpEnv.UpdateOne(updateData)
	})
}

func (qdb *QueryDataBaseDTO) UpdateDBInfo() error {
	return hotReloadDBCfg(func() error {
		updateData := qdb.toORMData()
		tmpDB := dbo.QueryDataBase{UID: qdb.UID}
		return tmpDB.UpdateOne(updateData)
	})
}

func (env *QueryEnvDTO) DeleteEnvInfo() error {
	return hotReloadDBCfg(func() error {
		temp := dbo.QueryEnv{
			UID: env.UID,
		}
		return temp.DeleteOne()
	})
}

func (qdb *QueryDataBaseDTO) DeleteDBInfo() error {
	return hotReloadDBCfg(func() error {
		temp := dbo.QueryDataBase{
			UID: qdb.UID,
		}
		return temp.DeleteOne()
	})
}
