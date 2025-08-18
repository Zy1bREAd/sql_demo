// 仅限SQL DEMO应用所使用的数据库操作
package dbo

import (
	"errors"
	"fmt"
	"sql_demo/internal/conf"
	"sql_demo/internal/utils"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var selfDB *SelfDatabase

type SelfDatabase struct {
	conn *gorm.DB
}

func HaveSelfDB() *SelfDatabase {
	if selfDB != nil {
		return selfDB
	}
	return nil
}
func (db *SelfDatabase) GetConn() *gorm.DB {
	return db.conn
}

func connect(dsn string, maxIdle, maxConn int) error {
	if selfDB == nil {
		gdb, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return utils.GenerateError("DB Connect Failed", "sql demo self db unable to connect")
		}
		dbPool, err := gdb.DB()
		if err != nil {
			return utils.GenerateError("DB Connect Failed", "db conn pool init failed")
		}
		dbPool.SetConnMaxIdleTime(time.Duration(maxIdle))
		dbPool.SetMaxOpenConns(maxConn)
		selfDB = &SelfDatabase{
			conn: gdb,
		}
		return nil
	}
	// 健康检查决定连接成败
	return selfDB.healthCheck()
}

// 初始化自身数据库连接配置
func InitSelfDB() *SelfDatabase {
	config := conf.GetAppConf().GetBaseConfig()
	for driver, conf := range config.DBEnv {
		// 判断不同数据库驱动选择不同的连接方式
		switch {
		case strings.ToLower(driver) == "mysql":
			err := connect(conf.DSN, conf.IdleTime, conf.MaxConn)
			if err != nil {
				panic(utils.GenerateError("????", err.Error()))
			}
		default:
			panic(utils.GenerateError("DB Driver Not Found", "driver not found"))
		}
	}

	// auto迁移表
	err := selfDB.autoMigrator()
	if err != nil {
		newErr := utils.GenerateError("AutoMigratorFailed", err.Error())
		panic(newErr)
	}
	return selfDB
}

func (db *SelfDatabase) Close() {
	dber, _ := db.conn.DB()
	dber.Close()
}

func (db *SelfDatabase) healthCheck() error {
	temp, err := db.conn.DB()
	if err != nil {
		return err
	}
	return temp.Ping()
}

func (db *SelfDatabase) autoMigrator() error {
	if db == nil {
		return utils.GenerateError("Migrator Failed", "self db is not init")
	}
	// 表多的话要以注册的方式注册进来，避免手动一个个输入
	return db.conn.AutoMigrate(&User{}, &TempResultMap{}, &AuditRecordV2{}, &QueryDataBase{}, &QueryEnv{})
}

// 创建用户逻辑
func (usr *User) Create() error {
	// 事务开启
	dbConn := HaveSelfDB().GetConn()
	result := dbConn.Where("email = ?", usr.Email).First(&usr)
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// 注册用户：用户是否被注册
		return utils.GenerateError("UserExist", "user has been registerd")
	}
	tx := dbConn.Begin()
	// 创建User(避免明文传入)
	salt := utils.GenerateSalt()
	user := &User{
		Name:     usr.Name,
		Email:    usr.Email,
		Password: utils.EncryptWithSaltMd5(salt, usr.Password),
		CreateAt: time.Now(),
	}
	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		errMsg := fmt.Sprintln("create user is failed, ", err.Error())
		return utils.GenerateError("Insert Failed", errMsg)
	}

	//提交事务
	tx.Commit()
	return nil
}

// 登录(Basic)
func (usr *User) BasicLogin(inputPwd string) error {
	// 使用该用户相同的salt，对用户密码进行加密验证，与数据库的加密密码进行对比
	dbConn := HaveSelfDB().GetConn()
	result := dbConn.Where("email = ?", usr.Email).Where("user_type = ?", 0).First(&usr)
	if result.Error != nil {
		// 判断记录是否不存在
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			errMsg := fmt.Sprintf("the account=%s is not exist", usr.Email)
			return utils.GenerateError("UserNotExist", errMsg)
		}
		return result.Error
	}
	// 校验用户密码
	if ok := utils.ValidateValueWithMd5(inputPwd, usr.Password); !ok {
		return utils.GenerateError("LoginFailed", "the user account or password is incorrect")
	}
	// 登录成功
	// 过滤隐私关键字段（将结构体映射成专用响应结构体）
	return nil
}

// 登录（SSO gitlab）,最终返回用户id
func (usr *User) SSOLogin() (uint, error) {
	result := selfDB.conn.Where("name = ?", usr.Name).Where("email = ?", usr.Email).Where("user_type = ?", 2).First(&usr)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// 首次注册进入DB
			newSSOUser := &User{
				Name:     usr.Name,
				Email:    usr.Email,
				UserType: 2,
				CreateAt: time.Now(),
			}
			tx := selfDB.conn.Begin()
			if err := tx.Create(newSSOUser).Error; err != nil {
				tx.Rollback()
				errMsg := fmt.Sprintln("create sso user is failed, ", err.Error())
				return 0, utils.GenerateError("SSOUserError", errMsg)
			}
			//提交事务
			tx.Commit()
		}
		return 0, result.Error
	}
	// 用户登录日志插槽
	return usr.ID, nil
}

// User DTO
type UserAuditRecord struct {
	// 查询的环境
	Env          string    `json:"env"`
	SQLStatement string    `json:"statement"`
	DBName       string    `json:"db_name"`
	ExcuteTime   time.Time `json:"excute_time"`
}

func GetAuditRecordByUserID(userId string) ([]UserAuditRecord, error) {
	auditRecords := []AuditRecordV2{}
	res := selfDB.conn.Where("user_id = ?", userId).Order(
		clause.OrderByColumn{
			Column: clause.Column{
				Name: "time_stamp", // 按照时间戳排序获取前10条
			},
			Desc: true,
		}).Limit(10).Find(&auditRecords)
	if res.Error != nil {
		utils.DebugPrint("AuditRecordError", res.Error.Error())
		return nil, errors.New("<DBQueryFailed>" + res.Error.Error())
	}
	if res.RowsAffected == 0 {
		utils.DebugPrint("AuditRecordError", "audit records is null")
		return []UserAuditRecord{}, nil
	}
	// Convert DTO Object
	userRecords := make([]UserAuditRecord, 0, 10)
	// for _, record := range auditRecords {
	// 	userRecords = append(userRecords, UserAuditRecord{
	// 		// DBName: record.,?
	// 	})
	// }
	// DebugPrint("resultRows", auditRecords)
	return userRecords, nil
}

// 存储临时结果链接
func SaveTempResult(uukey, taskId string, expireTime uint, allowExport bool) error {
	now := time.Now().Add(time.Duration(expireTime) * time.Second)
	tempData := TempResultMap{
		UUKey:         uukey,
		TaskId:        taskId,
		ExpireAt:      now,
		IsAllowExport: allowExport,
	}
	res := selfDB.conn.Create(&tempData)
	if res.Error != nil {
		return res.Error
	}
	// 延时设置清理flag标志
	time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
		res := selfDB.conn.Model(&TempResultMap{}).Where("uu_key = ?", uukey).Where("task_id = ?", taskId).Update("is_deleted", 1)
		if res.Error != nil {
			utils.DebugPrint("DelTempResultError", "delete temp result link is failed "+res.Error.Error())
			return
		}
		if res.RowsAffected == 0 {
			utils.DebugPrint("DelTempResultError", "RowsAffected is zero")
			return
		}

	})
	return nil
}

// 从数据库中获取结果集是否存在、是否过期
func GetTempResult(uuKey string) (*TempResultMap, error) {
	var tempData TempResultMap
	res := selfDB.conn.Where("uu_key = ?", uuKey).First(&tempData)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("result link is not found")
		}
		return nil, res.Error
	}
	if tempData.IsDeleted != 0 || time.Now().After(tempData.ExpireAt) {
		// 标识过期已被删除
		return nil, errors.New("result link is deleted due to expired")
	}
	return &tempData, nil
}

func AllowResultExport(taskId string) bool {
	var tempData TempResultMap
	res := selfDB.conn.Where("task_id = ?", taskId).First(&tempData)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false
		}
		return false
	}
	if tempData.IsDeleted == 1 || time.Now().After(tempData.ExpireAt) {
		return false
	}
	return tempData.IsAllowExport
}

func (usr *User) GetGitLabUserId() uint {
	res := selfDB.conn.Where("git_lab_identity = ?", usr.GitLabIdentity).First(&usr)
	if res.Error != nil {
		utils.DebugPrint("DBAPIError", "get user id is failed")
		return 0
	}
	return usr.ID
}

func (v2 *AuditRecordV2) InsertOne(e string) error {
	v2.EventType = e
	db := HaveSelfDB()
	tx := db.conn.Begin()
	// 避免携带默认值插入污染导出相关信息
	result := selfDB.conn.Create(&v2)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("InsertRecordError", "insert audit record is failed")
	}
	tx.Commit()

	return nil
}

// 查看审计日志
func (v2 *AuditRecordV2) Get() ([]AuditRecordV2, error) {
	var records []AuditRecordV2
	db := HaveSelfDB()
	res := db.conn.Where(&v2).Find(&records)
	if res.Error != nil {
		return nil, utils.GenerateError("AuditRecordErr", res.Error.Error())
	}
	return records, nil
}

// 通过时间范围筛选s
func (v2 *AuditRecordV2) GetByTime(start, end time.Time) ([]AuditRecordV2, error) {
	var records []AuditRecordV2
	db := HaveSelfDB()
	res := db.conn.Where(&v2).Where("create_at BETWEEN ? AND ?").Find(&records)
	if res.Error != nil {
		return nil, utils.GenerateError("AuditRecordErr", res.Error.Error())
	}
	return records, nil
}

func (dbInfo *QueryDataBase) CreateOne() error {
	db := HaveSelfDB().GetConn()

	dbIst := dbInfo.Service
	envId := dbInfo.EnvID
	// 不存在则创建，反之不创建
	findRes := db.Where("env_id = ? AND service = ?", envId, dbIst).First(&dbInfo)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return utils.GenerateError("FindError", findRes.Error.Error())
	}
	if findRes.RowsAffected == 1 {
		return utils.GenerateError("CreateError", "the db instance is exist")
	}
	tx := db.Begin()
	insertRes := db.Create(&dbInfo)
	if insertRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("CreateError", insertRes.Error.Error())
	}
	if insertRes.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("CreateError", "insert data rows is error")
	}
	tx.Commit()
	return nil
}

func (env *QueryEnv) CreateOne() error {
	db := HaveSelfDB().GetConn()

	envName := env.Name
	// 不存在则创建，反之不创建
	findRes := db.Where("name = ?", envName).First(&env)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return utils.GenerateError("CreateError", findRes.Error.Error())
	}
	if findRes.RowsAffected == 1 {
		return utils.GenerateError("CreateError", "the env is exist")
	}
	tx := db.Begin()
	insertRes := db.Create(&env)
	if insertRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("CreateError", insertRes.Error.Error())
	}
	if insertRes.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("CreateError", "insert data rows is error")
	}
	tx.Commit()
	return nil
}

func (env *QueryEnv) LoadAll() ([]QueryEnv, error) {
	var envList []QueryEnv
	db := HaveSelfDB().GetConn()
	findRes := db.Find(&envList)
	if findRes.Error != nil {
		return nil, utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	// resultList := make([]QueryEnv, findRes.RowsAffected+1)
	return envList, nil
}

func (env *QueryDataBase) LoadAll() ([]QueryDataBase, error) {
	var dbList []QueryDataBase
	db := HaveSelfDB().GetConn()
	findRes := db.Find(&dbList)
	if findRes.Error != nil {
		return nil, utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	// resultList := make([]QueryEnv, findRes.RowsAffected+1)
	return dbList, nil
}

func (env *QueryEnv) UpdateOne(updateEnv *QueryEnv) error {
	db := HaveSelfDB().GetConn()
	findRes := db.Where("uid = ?", env.UID).First(&env)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return utils.GenerateError("UpdateFailed", "the env record is not exist:"+findRes.Error.Error())
		}
		return utils.GenerateError("UpdateFailed", findRes.Error.Error())
	}
	tx := db.Begin()
	updateEnv.ID = env.ID
	updateEnv.UpdateAt = time.Now()
	updateRes := db.Model(&env).Updates(updateEnv)
	if updateRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("UpdateFailed", findRes.Error.Error())
	}
	if updateRes.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("UpdateFailed", "update error is unkonwn")
	}
	tx.Commit()
	return nil
}

// 按照指定ID查找环境
func (env *QueryEnv) FindById(uid string) (*QueryEnv, error) {
	db := HaveSelfDB().GetConn()
	findRes := db.Where("uid = ?", uid).First(&env)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return nil, utils.GenerateError("UpdateFailed", "the env record is not exist:"+findRes.Error.Error())
		}
		return nil, utils.GenerateError("FindDataErr", findRes.Error.Error())
	}
	return env, nil
}

func (dbInfo *QueryDataBase) UpdateOne(updateDB *QueryDataBase) error {
	db := HaveSelfDB().GetConn()
	// 要事先确定外键ID，确保唯一性。
	findRes := db.Where("uid = ?", dbInfo.UID).First(&dbInfo)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return utils.GenerateError("UpdateFailed", "the db record is not exist:"+findRes.Error.Error())
		}
		return utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	tx := db.Begin()
	updateDB.ID = dbInfo.ID
	updateDB.UpdateAt = time.Now()
	fmt.Println("uuuuupdate", updateDB.Password)
	updateRes := db.Model(&dbInfo).Updates(updateDB)
	if updateRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	if updateRes.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("LoadAllEnv", "update error is unkonwn")
	}
	tx.Commit()
	return nil
}

func (env *QueryEnv) DeleteOne() error {
	db := HaveSelfDB().GetConn()
	tx := db.Begin()
	res := db.Where("uid = ?", env.UID).Delete(&env)
	if res.Error != nil {
		tx.Rollback()
		return utils.GenerateError("DeleteError", res.Error.Error())
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("DeleteError", "delete row error")
	}
	tx.Commit()
	return nil
}

func (qdb *QueryDataBase) DeleteOne() error {
	db := HaveSelfDB().GetConn()
	tx := db.Begin()
	res := db.Where("uid = ?", qdb.UID).Delete(&qdb)
	if res.Error != nil {
		tx.Rollback()
		return utils.GenerateError("DeleteError", res.Error.Error())
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("DeleteError", "delete row error")
	}
	tx.Commit()
	return nil
}
