package core

import (
	"crypto/rand"
	"fmt"
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
	EnvID      uint        `json:"env_id"` // 关键指定EnvID
	MaxConn    int         `json:"max_conn"`
	IdleTime   int         `json:"idle_time"`
	IsWrite    bool        `json:"is_write"`
	Name       string      `json:"name"`
	EnvName    string      `json:"env_name"`
	Service    string      `json:"service"`
	Desc       string      `json:"description,omitempty"`
	UpdateAt   time.Time   `json:"-"`
	Exclude    []string    `json:"exclude"` // 排除的数据库名
	Connection ConnectInfo `json:"connection"`
}

type QueryEnvDTO struct {
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Desc    string `json:"description"`
	IsWrite bool   `json:"is_write"`
}

func (env *QueryEnvDTO) toORMData() *dbo.QueryEnv {
	return &dbo.QueryEnv{
		Name:    env.Name,
		Tag:     env.Tag,
		Desc:    env.Desc,
		IsWrite: env.IsWrite,
	}
}

func (qdb *QueryDataBaseDTO) toORMData() *dbo.QueryDataBase {
	var excludeStr string
	for _, v := range qdb.Exclude {
		excludeStr += v + "|"
	}
	// 密码加密(AES256)
	secretKey := make([]byte, 32)
	_, err := rand.Read(secretKey)
	if err != nil {
		return nil
	}
	pwd, err := utils.EncryptAES256([]byte(qdb.Connection.Password), secretKey)
	if err != nil {
		utils.DebugPrint("EncryptPWDErr", err.Error())
		return nil
	}
	return &dbo.QueryDataBase{
		EnvID:    qdb.EnvID,
		MaxConn:  qdb.MaxConn,
		IdleTime: qdb.IdleTime,
		IsWrite:  qdb.IsWrite,
		Name:     qdb.Name,
		Service:  qdb.Service,
		Desc:     qdb.Desc,
		UpdateAt: qdb.UpdateAt,
		Exclude:  excludeStr,
		Host:     qdb.Connection.Host,
		User:     qdb.Connection.User,
		Password: pwd,
		Port:     qdb.Connection.Port,
		TLS:      qdb.Connection.TLS,
		Salt:     secretKey,
	}
}

func (qdb *QueryDataBaseDTO) Create() error {

	defer func() {
		// 触发热加载配置
		dbo.LoadInDB(true)
	}()
	//数据转换到db model中
	orm := qdb.toORMData()
	fmt.Println(&orm, orm)
	err := orm.CreateOne()
	if err != nil {
		return err
	}
	return nil
}

func (env *QueryEnvDTO) Create() error {
	defer func() {
		// 触发热加载配置
		dbo.LoadInDB(true)
	}()
	//数据转换到db model中
	orm := env.toORMData()
	err := orm.CreateOne()
	if err != nil {
		return err
	}
	return nil
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

func (env *QueryEnvDTO) UpdateEnvInfo(id int) error {
	updateData := env.toORMData()
	var temp dbo.QueryEnv
	envId := uint(id)
	envData, err := temp.FindById(id)
	if err != nil {
		return err
	}
	if envData.ID != envId {
		return utils.GenerateError("EnvIdError", "EnvId is not match")
	}
	updateData.ID = envId
	err = envData.UpdateOne(updateData)
	if err != nil {
		return err
	}
	return nil
}
