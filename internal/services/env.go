package services

import (
	"slices"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"strings"
)

// 服务层，封装Core函数组成业务性函数、方法
type EnvSerivce struct {
	DAO dbo.QueryEnv
}

func NewEnvService() EnvSerivce {
	return EnvSerivce{
		DAO: dbo.QueryEnv{}, // 空结构体，用于操作数据库层面的接口
	}
}

// 转换成ORM数据Model对象
func (env *EnvSerivce) toORMData(dto dto.QueryEnvDTO) *dbo.QueryEnv {
	var tagStr string
	for _, t := range dto.Tag {
		tagStr += t + ","
	}
	return &dbo.QueryEnv{
		UID:         dto.UID,
		Name:        dto.Name,
		Tag:         tagStr,
		Description: dto.Desc,
		IsWrite:     dto.IsWrite,
		// 不加入Time类型
	}
}

// 转换成DTO数据传输对象
func (env *EnvSerivce) toDTOData(orm dbo.QueryEnv) *dto.QueryEnvDTO {
	return &dto.QueryEnvDTO{
		UID:      orm.UID,
		Name:     orm.Name,
		Tag:      strings.Split(orm.Tag, ","),
		Desc:     orm.Description,
		CreateAt: orm.CreateAt.Format("2006-01-02 15:04:05"),
		UpdateAt: orm.UpdateAt.Format("2006-01-02 15:04:05"),
		IsWrite:  orm.IsWrite,
	}
}

// 创建Env数据（可返回UID）
func (env *EnvSerivce) Create(data dto.QueryEnvDTO) error {
	return hotReloadDBCfg(func() error {
		dataORM := env.toORMData(data)
		dataORM.UID = utils.GenerateUUIDKey()
		return env.DAO.CreateOne(dataORM)
	})
}

// 删除指定的环境
func (env *EnvSerivce) Delete(cond dto.QueryEnvDTO) error {
	condORM := env.toORMData(cond)
	return hotReloadDBCfg(func() error {
		return env.DAO.DeleteOne(condORM)
	})
}

// 按照条件进行更新
func (env *EnvSerivce) UpdateInfo(cond, update dto.QueryEnvDTO) error {
	return hotReloadDBCfg(func() error {
		updateORM := env.toORMData(update)
		condORM := env.toORMData(cond)
		return env.DAO.UpdateOne(condORM, updateORM)
	})
}

// 获取所有的Env
func (env *EnvSerivce) Get(cond dto.QueryEnvDTO, pagni *common.Pagniation) ([]dto.QueryEnvDTO, error) {
	condORM := env.toORMData(cond)
	envRes, err := env.DAO.Find(condORM, pagni)
	if err != nil {
		return nil, err
	}

	// 格式化
	DTOResults := make([]dto.QueryEnvDTO, len(envRes))
	for _, result := range envRes {
		data := env.toDTOData(result)
		DTOResults = append(DTOResults, *data)
	}
	return DTOResults, nil
}

// 从DBPool中读取所有Env名字
func (env *EnvSerivce) NameListWithPool() []string {
	dbManger := dbo.GetDBPoolManager()
	envList := make([]string, 0, len(dbManger.Pool))
	for envKey := range dbManger.Pool {
		envList = append(envList, envKey)
	}
	// 新增排序功能
	slices.Sort(envList)
	return envList
}

// ! 核心函数：热加载的封装执行
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
