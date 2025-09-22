package services

import (
	"crypto/rand"
	"slices"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"strings"
)

type SourcesService struct {
	DAO dbo.QueryDataBase
}

func NewSourceService() SourcesService {
	return SourcesService{
		DAO: dbo.QueryDataBase{}, // 空结构体，用于操作数据库层面的接口
	}
}

func (source *SourcesService) toORMData(dto dto.QueryDataBaseDTO) *dbo.QueryDataBase {
	var excludeDBStr, excludeTableStr string
	for _, d := range dto.ExcludeDB {
		excludeDBStr += d + ","
	}
	for _, t := range dto.ExcludeTable {
		excludeTableStr += t + ","
	}
	var pwd string
	var secretKey []byte
	if dto.Connection.Password != "" {
		// 密码加密(AES256)
		secretKey = make([]byte, 32)
		_, err := rand.Read(secretKey)
		if err != nil {
			return nil
		}
		pwd, err = utils.EncryptAES256([]byte(dto.Connection.Password), secretKey)
		if err != nil {
			utils.DebugPrint("EncryptPWDErr", err.Error())
			return nil
		}
	}
	return &dbo.QueryDataBase{
		EnvID:           dto.EnvID,
		UID:             dto.UID,
		MaxConn:         dto.Connection.MaxConn,
		IdleTime:        dto.Connection.IdleTime,
		IsWrite:         dto.IsWrite,
		Name:            dto.Name,
		Service:         dto.Service,
		Description:     dto.Desc,
		ExcludeDB:       excludeDBStr,
		ExcludeTable:    excludeTableStr,
		Host:            dto.Connection.Host,
		User:            dto.Connection.User,
		Password:        pwd,
		Port:            dto.Connection.Port,
		TLS:             dto.Connection.TLS,
		Salt:            secretKey,
		ConfirmPassword: dto.ConfirmedPassword, // 用户输入的旧密码，需要校验的
	}
}

func (source *SourcesService) toDTOData(orm dbo.QueryDataBase) *dto.QueryDataBaseDTO {
	// 不涉及敏感数据
	return &dto.QueryDataBaseDTO{
		EnvID:        orm.EnvID,
		UID:          orm.UID,
		IsWrite:      orm.IsWrite,
		Name:         orm.Name,
		EnvName:      orm.EnvForKey.Name, // 获取环境变量的名字
		Service:      orm.Service,
		Desc:         orm.Description,
		ExcludeDB:    strings.Split(strings.Trim(orm.ExcludeDB, ","), ","),
		ExcludeTable: strings.Split(strings.Trim(orm.ExcludeTable, ","), ","),
		Connection: dbo.ConnectInfo{
			Host:     orm.Host,
			User:     orm.User,
			Port:     orm.Port,
			TLS:      orm.TLS,
			MaxConn:  orm.MaxConn,
			IdleTime: orm.IdleTime,
		},
		CreateAt: orm.CreateAt.Format("2006-01-02 15:04:05"),
		UpdateAt: orm.UpdateAt.Format("2006-01-02 15:04:05"),
	}
}

// 创建数据源
func (source *SourcesService) Create(data dto.QueryDataBaseDTO) error {
	return hotReloadDBCfg(func() error {
		dataORM := source.toORMData(data)
		// 分配uuid
		dataORM.UID = utils.GenerateUUIDKey()
		envID, err := dataORM.GetEnvID(data.EnvName)
		dataORM.EnvID = envID
		if err != nil {
			return err
		}
		return source.DAO.CreateOne(dataORM)
	})
}

// 删除特定的数据源
func (source *SourcesService) Delete(cond dto.QueryDataBaseDTO) error {
	return hotReloadDBCfg(func() error {
		condORM := source.toORMData(cond)
		return source.DAO.DeleteOne(condORM)
	})
}

func (source *SourcesService) Update(cond, data dto.QueryDataBaseDTO) error {
	return hotReloadDBCfg(func() error {
		updateORM := source.toORMData(data)
		condORM := source.toORMData(cond)
		return source.DAO.UpdateOne(condORM, updateORM)
	})
}

// 获取指定环境下所有db实例
func (source *SourcesService) DBIstListWithPool(env string) []string {
	istNameList := []string{}
	dbMgr := dbo.GetDBPoolManager()
	for istName := range dbMgr.Pool[env] {
		istNameList = append(istNameList, istName)
	}
	// 新增排序功能
	slices.Sort(istNameList)
	return istNameList
}

// 获取所有环境下的db实例（若切片参数没有定义则是获取全部）
func (source *SourcesService) Get(cond dto.QueryDataBaseDTO, pagni *common.Pagniation) (map[string][]dto.QueryDataBaseDTO, error) {
	// 获取所有Env列表
	var allDBInfoMap map[string][]dto.QueryDataBaseDTO = make(map[string][]dto.QueryDataBaseDTO)
	var dbResult []dbo.QueryDataBase
	condORM := source.toORMData(cond)
	dbResult, err := source.DAO.Find(condORM, pagni)
	if err != nil {
		return nil, err
	}

	for _, data := range dbResult {
		if data.EnvForKey.Name == "" {
			continue
		}
		envKey := data.EnvForKey.Name
		allDBInfoMap[envKey] = append(allDBInfoMap[envKey], *source.toDTOData(data))
	}
	return allDBInfoMap, nil
}

// 通过关键字过滤查找数据源信息
func (source *SourcesService) FilterKeyWord(keyword string, pagni *common.Pagniation) (map[string][]dto.QueryDataBaseDTO, error) {
	// 获取所有Env列表
	var allDBInfoMap map[string][]dto.QueryDataBaseDTO = make(map[string][]dto.QueryDataBaseDTO)
	var dbResult []dbo.QueryDataBase
	var err error
	//! 判断是否以关键词进行查询
	if keyword == "" {
		dbResult, err = source.DAO.Find(&dbo.QueryDataBase{}, pagni)
	} else {
		dbResult, err = source.DAO.FindByKeyWord(keyword, pagni)
	}
	if err != nil {
		return nil, err
	}

	for _, data := range dbResult {
		if data.EnvForKey.Name == "" {
			continue
		}
		envKey := data.EnvForKey.Name
		allDBInfoMap[envKey] = append(allDBInfoMap[envKey], *source.toDTOData(data))
	}
	return allDBInfoMap, nil
}
