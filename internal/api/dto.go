package api

import (
	"crypto/rand"
	"errors"
	"slices"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"strings"

	"gorm.io/gorm"
)

// DTO: Data Transfer Object + Service Layer

type QueryDataBaseDTO struct {
	EnvID             uint            `json:"env_id"` // 关键指定EnvID
	IsWrite           bool            `json:"is_write"`
	Name              string          `json:"name"`
	UID               string          `json:"uid"`
	EnvName           string          `json:"env_name"`
	Service           string          `json:"service"`
	Desc              string          `json:"description,omitempty"`
	CreateAt          string          `json:"create_at"`
	UpdateAt          string          `json:"update_at"`
	ExcludeDB         []string        `json:"exclude_db"`    // 排除的数据库名
	ExcludeTable      []string        `json:"exclude_table"` // 排除的数据表名
	Connection        dbo.ConnectInfo `json:"connection"`    // 连接信息
	ConfirmedPassword string          `json:"confirm_pwd"`   // 二次验证新密码

}

type QueryEnvDTO struct {
	IsWrite  bool     `json:"is_write"`
	UID      string   `json:"uid"`
	Name     string   `json:"name"`
	Tag      []string `json:"tag"`
	Desc     string   `json:"description"`
	CreateAt string   `json:"create_at"`
	UpdateAt string   `json:"update_at"`
}

type AuditRecordDTO struct {
	ProjectID uint   `json:"project_id"`
	IssueID   uint   `json:"issue_id"`
	TaskType  int    `json:"task_type"`
	TaskID    string `json:"task_id"`
	UserName  string `json:"username"`
	EventType string `json:"event_type"`
	Payload   string `json:"payload"`
	CreateAt  string `json:"create_at"`
	// 时间范围筛选条件项
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
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

// 请求SQL任务的 DTO
type SQLTaskRequestDTO struct {
	Env       string `json:"env" validate:"required"`
	Service   string `json:"service" validate:"required"`
	DBName    string `json:"db_name" validate:"required"`
	Statement string `json:"statement" validate:"required,min=1"`
	LongTime  bool   `json:"long_time"`
	IsExport  bool   `json:"is_export"`
	IsSOAR    bool   `json:"is_soar"`
}

func (dto SQLTaskRequestDTO) Validate() error {
	va := utils.NewValidator()
	err := va.Struct(&dto)
	if err != nil {
		return err
	}
	return nil
}

// 部分转换
func (dto *AuditRecordDTO) toORMData() *dbo.AuditRecordV2 {
	return &dbo.AuditRecordV2{
		TaskID:    dto.TaskID,
		EventType: dto.EventType,
		StartTime: dto.StartTime,
		EndTime:   dto.EndTime,
		//! 新增按照用户来查找
	}
}

// 转化成DB查询的条件
func (dto *AuditRecordDTO) toCondsData() *dbo.AuditRecordV2 {
	return &dbo.AuditRecordV2{
		TaskID:    dto.TaskID,
		EventType: dto.EventType,
		StartTime: dto.StartTime,
		EndTime:   dto.EndTime,
		//! 新增按照用户来查找
	}
}

func (dto *AuditRecordDTO) Get(pagni *common.Pagniation) ([]AuditRecordDTO, error) {
	orm := dto.toORMData()
	// 如果按照用户名查找，需要判断该用户是否存在
	if dto.UserName != "" {
		dbConn := dbo.HaveSelfDB().GetConn()
		var user dbo.User
		res := dbConn.Where("name = ?", dto.UserName).Last(&user)
		if res.Error != nil {
			if errors.Is(res.Error, gorm.ErrRecordNotFound) {
				return nil, utils.GenerateError("UserNotFound", dto.UserName+" The user is not exist")
			}
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, utils.GenerateError("UserNotFound", dto.UserName+" The user is not exist")
		}
		orm.UserID = user.ID
	}
	sqlResult, err := orm.Find(pagni)
	if err != nil {
		return nil, err
	}
	// 加入分页
	result := make([]AuditRecordDTO, 0, pagni.PageSize)
	for _, record := range sqlResult {
		result = append(result, AuditRecordDTO{
			TaskID:    record.TaskID,
			EventType: record.EventType,
			CreateAt:  record.CreateAt.Format("2006-01-02 15:04:05"),
			TaskType:  record.TaskKind,
			ProjectID: record.ProjectID,
			IssueID:   record.IssueID,
			UserName:  record.User.Name,
			Payload:   record.Payload,
		})
	}
	return result, nil
}

func (env *QueryEnvDTO) toORMData() *dbo.QueryEnv {
	var tagStr string
	for _, t := range env.Tag {
		tagStr += t + ","
	}
	return &dbo.QueryEnv{
		UID:         env.UID,
		Name:        env.Name,
		Tag:         tagStr,
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
	var secretKey []byte
	if qdb.Connection.Password != "" {
		// 密码加密(AES256)
		secretKey = make([]byte, 32)
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
		EnvID:           qdb.EnvID,
		UID:             qdb.UID,
		MaxConn:         qdb.Connection.MaxConn,
		IdleTime:        qdb.Connection.IdleTime,
		IsWrite:         qdb.IsWrite,
		Name:            qdb.Name,
		Service:         qdb.Service,
		Description:     qdb.Desc,
		ExcludeDB:       excludeDBStr,
		ExcludeTable:    excludeTableStr,
		Host:            qdb.Connection.Host,
		User:            qdb.Connection.User,
		Password:        pwd,
		Port:            qdb.Connection.Port,
		TLS:             qdb.Connection.TLS,
		Salt:            secretKey,
		ConfirmPassword: qdb.ConfirmedPassword, // 用户输入的旧密码，需要校验的
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
		err := orm.FindEnvID(qdb.EnvName)
		if err != nil {
			return err
		}
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
func (source *QueryDataBaseDTO) GetorSearch(keyword string, pagni *common.Pagniation) (map[string][]QueryDataBaseDTO, error) {
	// 获取所有Env列表
	var allDBInfoMap map[string][]QueryDataBaseDTO = make(map[string][]QueryDataBaseDTO)
	var dbResult []dbo.QueryDataBase
	var err error
	// 添加每个Env下的db信息列表
	var dbDTO QueryDataBaseDTO
	orm := dbDTO.toORMData()
	//! 判断是否以关键词进行查询
	if keyword == "" {
		dbResult, err = orm.Find(pagni)
	} else {
		dbResult, err = orm.FindByKeyWord(keyword, pagni)
	}
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
			IsWrite:      data.IsWrite,
			EnvID:        data.EnvID,
			Connection: dbo.ConnectInfo{
				User: data.User,
				// Password: data.Password,
				Host:     data.Host,
				Port:     data.Port,
				TLS:      data.TLS,
				MaxConn:  data.MaxConn,
				IdleTime: data.IdleTime,
			},
			CreateAt: data.CreateAt.Format("2006-01-02 15:04:05"),
			UpdateAt: data.UpdateAt.Format("2006-01-02 15:04:05"),
		})
	}
	return allDBInfoMap, nil
}

// 获取所有的Env
func (env *QueryEnvDTO) Get(pagni *common.Pagniation) ([]QueryEnvDTO, error) {
	orm := env.toORMData()
	res, err := orm.Find(pagni)
	if err != nil {
		return nil, err
	}
	// 格式化好DTO进行返回
	resultList := make([]QueryEnvDTO, 0, len(res))
	for _, env := range res {
		resultList = append(resultList, QueryEnvDTO{
			UID:      env.UID,
			Name:     env.Name,
			Tag:      strings.Split(env.Tag, ","),
			Desc:     env.Description,
			CreateAt: env.CreateAt.Format("2006-01-02 15:04:05"),
			UpdateAt: env.UpdateAt.Format("2006-01-02 15:04:05"),
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

func (qdb *QueryDataBaseDTO) Delete() error {
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
