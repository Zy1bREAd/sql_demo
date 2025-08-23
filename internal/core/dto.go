package core

import (
	"crypto/rand"
	"fmt"
	"slices"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"strings"
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
	IsWrite  bool   `json:"is_write"`
	UID      string `json:"uid"`
	Name     string `json:"name"`
	Tag      string `json:"tag"`
	Desc     string `json:"description"`
	CreateAt string `json:"create_at"`
	UpdateAt string `json:"update_at"`
}

type AuditRecordDTO struct {
	ProjectID uint      `json:"project_id"`
	IssueID   uint      `json:"issue_id"`
	TaskType  int       `json:"task_type"`
	UserName  string    `json:"username"`
	EventType string    `json:"event_type"`
	TaskID    string    `json:"task_id"`
	Payload   string    `json:"payload"`
	CreateAt  time.Time `json:"create_at"`
}

// TicketStatusStats 票据状态统计 DTO（数据传输对象）
type TicketStatusStatsDTO struct {
	CreatedCount        int `json:"created_count"`         // 创建状态数量
	ApprovalPassedCount int `json:"approval_passed_count"` // 审批通过数量
	ApprovalRejectCount int `json:"approval_reject_count"` // 审批拒绝数量
	ExecutePendingCount int `json:"execute_pending_count"` // 执行中（待处理）数量
	PendingCount        int `json:"pending_count"`         // 待处理数量
	CompletedCount      int `json:"completed_count"`       // 已完成数量
	FailedCount         int `json:"failed_count"`          // 失败数量
	TotalCount          int `json:"total_count"`
}

func (dto *AuditRecordDTO) toORMData() *dbo.AuditRecordV2 {
	return &dbo.AuditRecordV2{
		TaskID:    dto.TaskID,
		EventType: dto.EventType,
		CreatAt:   dto.CreateAt,
	}
}

func (dto *AuditRecordDTO) Get() ([]AuditRecordDTO, error) {
	orm := dto.toORMData()
	// 如果按照用户名查找，需要判断该用户是否存在
	if dto.UserName != "" {
		dbConn := dbo.HaveSelfDB().GetConn()
		var user dbo.User
		res := dbConn.Where("name = ?", dto.UserName).Last(&user)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, utils.GenerateError("UserNotFound", dto.UserName+" The user is not exist")
		}
		orm.UserID = user.ID
	}
	sqlResult, err := orm.Find()
	if err != nil {
		return nil, err
	}
	result := make([]AuditRecordDTO, 0, len(sqlResult))
	for _, record := range sqlResult {
		result = append(result, AuditRecordDTO{
			TaskID:    record.TaskID,
			EventType: record.EventType,
			CreateAt:  record.CreatAt,
			TaskType:  record.TaskType,
			ProjectID: record.ProjectID,
			IssueID:   record.IssueID,
			UserName:  dto.UserName,
			Payload:   record.Payload,
		})
	}
	return result, nil
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
func (env *QueryEnvDTO) GetEnvNameList() []string {
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

// 获取所有环境下的db实例（若切片参数没有定义则是获取全部）
func (env *QueryEnvDTO) GetDBList(envNameList []string) (map[string][]QueryDataBaseDTO, error) {
	// 获取所有Env列表
	var allDBInfoMap map[string][]QueryDataBaseDTO = make(map[string][]QueryDataBaseDTO)
	if len(envNameList) == 0 {
		envNameList = env.GetEnvNameList()
	}
	for _, env := range envNameList {
		allDBInfoMap[env] = nil
	}

	// 添加每个Env下的db信息列表
	var dbDTO QueryDataBaseDTO
	dbResult, err := dbDTO.toORMData().Find()
	if err != nil {
		return nil, err
	}
	for _, data := range dbResult {
		if data.EnvForKey.Name == "" {
			continue
		}
		envKey := data.EnvForKey.Name
		allDBInfoMap[envKey] = append(allDBInfoMap[envKey], QueryDataBaseDTO{
			UID:          data.UID,
			Name:         data.Name,
			EnvName:      data.EnvForKey.Name,
			Service:      data.Service,
			Desc:         data.Description,
			ExcludeDB:    strings.Split(data.ExcludeDB, ","),
			ExcludeTable: strings.Split(data.ExcludeTable, ","),
			MaxConn:      data.MaxConn,
			IdleTime:     data.IdleTime,
			IsWrite:      data.IsWrite,
			EnvID:        data.EnvID,
			Connection: ConnectInfo{
				User: data.User,
				// Password: data.Password,
				Host: data.Host,
				Port: data.Port,
				TLS:  data.TLS,
			},
		})
	}
	return allDBInfoMap, nil
}

// 获取所有的Env
func (env *QueryEnvDTO) GetAllData() ([]QueryEnvDTO, error) {
	orm := env.toORMData()
	res, err := orm.FindAll()
	if err != nil {
		return nil, err
	}
	fmt.Println(dbo.GetDBPoolManager().Pool)
	// 格式化好DTO进行返回
	resultList := make([]QueryEnvDTO, 0, len(res))
	for _, env := range res {
		resultList = append(resultList, QueryEnvDTO{
			UID:      env.UID,
			Name:     env.Name,
			Tag:      env.Tag,
			Desc:     env.Description,
			CreateAt: env.CreateAt.Format("20060102150405"),
			UpdateAt: env.UpdateAt.Format("20060102150405"),
			IsWrite:  env.IsWrite,
		})
	}
	return resultList, nil

}

// 仅获取不同Env下的实例名称列表
func OnlyDBNameList() map[string][]string {
	temp := make(map[string][]string, 10)
	env := QueryEnvDTO{}
	qdb := QueryDataBaseDTO{}
	envResult := env.GetEnvNameList()
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

func (dto *TicketStatusStatsDTO) StatsCount() (map[string]int, error) {
	var t dbo.Ticket
	resultMap, err := t.StatsCount()
	if err != nil {
		return nil, err
	}
	return resultMap, nil
}
