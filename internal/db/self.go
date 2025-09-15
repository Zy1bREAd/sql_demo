// 仅限SQL DEMO应用所使用的数据库操作
package dbo

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/utils"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
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
	return db.conn.AutoMigrate(&User{}, &TempResultMap{}, &AuditRecordV2{}, &QueryDataBase{}, &QueryEnv{}, &Ticket{})
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
func (usr *User) SSOLogin(cond User) (uint, error) {
	dbConn := HaveSelfDB().GetConn()
	result := dbConn.Model(cond).First(&usr)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// 首次注册进入DB
			newSSOUser := &User{
				Name:           usr.Name,
				Email:          usr.Email,
				UserType:       GITLABUSER,
				GitLabIdentity: usr.ID,
				CreateAt:       time.Now(),
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

// 通过UserID判断
func (usr *User) IsAdminUser() bool {
	var resultUser User
	dbConn := HaveSelfDB().GetConn()
	res := dbConn.Where(User{
		ID: usr.ID,
	}).Last(&resultUser)
	if res.Error != nil {
		return false
	}
	if res.RowsAffected != 1 {
		return false
	}
	if resultUser.Role != AdministratorRole {
		return false
	}
	return true
}

func (usr *User) GetGitLabUserId() uint {
	res := selfDB.conn.Where("git_lab_identity = ?", usr.GitLabIdentity).First(&usr)
	if res.Error != nil {
		utils.DebugPrint("DBAPIError", "get user id is failed")
		return 0
	}
	return usr.ID
}

// // User DTO
// type UserAuditRecord struct {
// 	// 查询的环境
// 	Env          string    `json:"env"`
// 	SQLStatement string    `json:"statement"`
// 	DBName       string    `json:"db_name"`
// 	ExcuteTime   time.Time `json:"excute_time"`
// }

// func GetAuditRecordByUserID(userId string) ([]UserAuditRecord, error) {
// 	auditRecords := []AuditRecordV2{}
// 	res := selfDB.conn.Where("user_id = ?", userId).Order(
// 		clause.OrderByColumn{
// 			Column: clause.Column{
// 				Name: "time_stamp", // 按照时间戳排序获取前10条
// 			},
// 			Desc: true,
// 		}).Limit(10).Find(&auditRecords)
// 	if res.Error != nil {
// 		utils.DebugPrint("AuditRecordError", res.Error.Error())
// 		return nil, errors.New("<DBQueryFailed>" + res.Error.Error())
// 	}
// 	if res.RowsAffected == 0 {
// 		utils.DebugPrint("AuditRecordError", "audit records is null")
// 		return []UserAuditRecord{}, nil
// 	}
// 	// Convert DTO Object
// 	userRecords := make([]UserAuditRecord, 0, 10)
// 	// for _, record := range auditRecords {
// 	// 	userRecords = append(userRecords, UserAuditRecord{
// 	// 		// DBName: record.,?
// 	// 	})
// 	// }
// 	// DebugPrint("resultRows", auditRecords)
// 	return userRecords, nil
// }

// 存储临时结果链接
func SaveTempResult(ticketID int64, uukey string, expireTime uint, allowExport bool) error {
	now := time.Now().Add(time.Duration(expireTime) * time.Second)
	tempData := TempResultMap{
		UID:           uukey,
		TicketID:      ticketID,
		ExpireAt:      now,
		IsAllowExport: allowExport,
	}
	res := selfDB.conn.Create(&tempData)
	if res.Error != nil {
		return res.Error
	}
	// 延时设置清理flag标志
	time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
		res := selfDB.conn.Model(&TempResultMap{}).Where("uid = ?", uukey).Where("ticket_id = ?", ticketID).Update("is_deleted", 1)
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
	res := selfDB.conn.Where("uid = ?", uuKey).First(&tempData)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("result link is not found")
		}
		return nil, res.Error
	}
	if tempData.IsDeleted != 0 || time.Now().After(tempData.ExpireAt) {
		// 标识过期已被删除
		return nil, utils.GenerateError("ResultExpiredErr", "Results and Result-Link is deleted due to expired")
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

func (v2 *AuditRecordV2) InsertOne(eventType string) error {
	v2.EventType = eventType
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

func (v2 *AuditRecordV2) Find(pagni *common.Pagniation) ([]AuditRecordV2, error) {
	var records []AuditRecordV2
	dbConn := HaveSelfDB().GetConn()
	// 抽象基础查询链
	tx := dbConn.Model(&AuditRecordV2{}).Preload("User").Where(&v2)
	// 判断时间范围筛选条件是否有效
	if v2.StartTime != "" && v2.EndTime != "" {
		//! 没有判断endtime小于starttime的情况
		tx = tx.Where("create_at BETWEEN ? AND ?", v2.StartTime, v2.EndTime)
	}
	// 查询总条数
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, err
	}
	// 通过指针修改源Total数量
	//! 防止无效分页请求
	if pagni.Page != 0 && pagni.PageSize != 0 {
		if (int(total)/pagni.PageSize)+1 < pagni.Page {
			return nil, utils.GenerateError("PageErr", "Page must be too big")
		}
		tx = tx.Offset(pagni.Offset).Limit(pagni.PageSize)
	}
	pagni.SetTotal(int(total))

	// 正式查询结果
	res := tx.Find(&records)
	if res.Error != nil {
		return nil, utils.GenerateError("AuditRecordErr", res.Error.Error())
	}
	return records, nil
}

// 通过时间范围筛选s
func (v2 *AuditRecordV2) FindByTime(start, end time.Time) ([]AuditRecordV2, error) {
	var records []AuditRecordV2
	db := HaveSelfDB()
	res := db.conn.Where(&v2).Where("create_at BETWEEN ? AND ?").Find(&records)
	if res.Error != nil {
		return nil, utils.GenerateError("AuditRecordErr", res.Error.Error())
	}
	return records, nil
}

func (source *QueryDataBase) CreateOne() error {
	db := HaveSelfDB().GetConn()

	dbIst := source.Service
	envId := source.EnvID
	// 不存在则创建，反之不创建
	findRes := db.Where("env_id = ? AND service = ?", envId, dbIst).First(&source)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return utils.GenerateError("FindError", findRes.Error.Error())
	}
	if findRes.RowsAffected == 1 {
		return utils.GenerateError("CreateError", "the db instance is exist")
	}
	tx := db.Begin()
	insertRes := db.Create(&source)
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

// 默认查找全部Env
func (env *QueryEnv) Find(pagni *common.Pagniation) ([]QueryEnv, error) {
	var envList []QueryEnv
	dbConn := HaveSelfDB().GetConn()
	// 构造基础查询链
	tx := dbConn.Model(&QueryEnv{}).Where(&env)
	// 查询总条数
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, err
	}
	//! 防止无效分页请求(前提是分页器有数据，像初始化时分页器无数据则无需判断)
	if pagni.Page != 0 && pagni.PageSize != 0 {
		if (int(total)/pagni.PageSize)+1 < pagni.Page {
			return nil, utils.GenerateError("PageErr", "Page must be too big")
		}
		tx = tx.Offset(pagni.Offset).Limit(pagni.PageSize)
	}
	pagni.SetTotal(int(total))

	findRes := tx.Find(&envList)
	if findRes.Error != nil {
		return nil, utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	return envList, nil
}

// 从DB中查找EnvName
func (env *QueryEnv) FindEnvName() ([]string, error) {
	db := HaveSelfDB().GetConn()
	var envNames []QueryEnv
	findRes := db.Select("name").Order("name").Find(&envNames)
	if findRes.Error != nil {
		return nil, utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	var result []string
	for _, e := range envNames {
		result = append(result, e.Name)
	}
	return result, nil
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

func (source *QueryDataBase) FindEnvID(envName string) error {
	db := HaveSelfDB().GetConn()
	var envResult QueryEnv
	res := db.Model(&QueryEnv{}).Where("name = ?", envName).Last(&envResult)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return utils.GenerateError("FindError", "The env is not exist")
	}
	source.EnvID = envResult.ID
	return nil
}

// 查找全部
func (source *QueryDataBase) Find(pagni *common.Pagniation) ([]QueryDataBase, error) {
	var dbList []QueryDataBase
	db := HaveSelfDB().GetConn()
	// 构造基础查询链
	tx := db.Model(&QueryDataBase{}).Preload("EnvForKey")
	// 查询总条数
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, err
	}
	//! 防止无效分页请求(前提是分页器有数据，像初始化时分页器无数据则无需判断)
	if pagni.Page != 0 && pagni.PageSize != 0 {
		if (int(total)/pagni.PageSize)+1 < pagni.Page {
			return nil, utils.GenerateError("PageErr", "Page must be too big")
		}
		tx = tx.Offset(pagni.Offset).Limit(pagni.PageSize)
	}
	pagni.SetTotal(int(total))
	findRes := tx.Find(&dbList)
	if findRes.Error != nil {
		return nil, utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	return dbList, nil
}

func (source *QueryDataBase) FindByKeyWord(kw string, pagni *common.Pagniation) ([]QueryDataBase, error) {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Model(&QueryDataBase{}).Preload("EnvForKey")
	subTx := dbConn.Model(&QueryEnv{})
	var findRes []QueryDataBase
	// 基础查询链
	kw = "%" + kw + "%"
	tx = tx.Where("name LIKE ?", kw).Or("service LIKE ?", kw).Or("env_id IN (?)", subTx.Select("id").Where("name LIKE ?", kw))
	// 查询总条数
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, err
	}
	//! 防止无效分页请求(前提是分页器有数据，像初始化时分页器无数据则无需判断)
	if pagni.Page != 0 && pagni.PageSize != 0 {
		if (int(total)/pagni.PageSize)+1 < pagni.Page {
			return nil, utils.GenerateError("PageErr", "Page must be too big")
		}
		tx = tx.Offset(pagni.Offset).Limit(pagni.PageSize)
	}
	pagni.SetTotal(int(total))
	res := tx.Find(&findRes)
	if res.Error != nil {
		return nil, res.Error
	}
	return findRes, nil
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

func (source *QueryDataBase) UpdateOne(updateDB *QueryDataBase) error {
	db := HaveSelfDB().GetConn()
	// 要事先确定外键ID，确保唯一性。
	findRes := db.Where("uid = ?", source.UID).First(&source)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return utils.GenerateError("UpdateFailed", "the db record is not exist:"+findRes.Error.Error())
		}
		return utils.GenerateError("LoadAllEnv", findRes.Error.Error())
	}
	tx := db.Begin()
	// 修改密码(新旧密码都必须要填写)
	if updateDB.ConfirmPassword != "" && updateDB.Password != "" {
		// 更新时，若密码不为空，则代表要更新数据源的连接密码
		// 判断旧密码和新密码是否相同(使用解密出来对比)
		pwd, err := utils.DecryptAES256([]byte(source.Password), source.Salt)
		if err != nil {
			return utils.GenerateError("EncryptPWDErr", err.Error())
		}
		if pwd != updateDB.ConfirmPassword {
			return utils.GenerateError("PasswordError", "Input Old Password and Original Password is not match")
		}
		// 开始校验并存储新密码
		secretKey := make([]byte, 32)
		_, err = rand.Read(secretKey)
		if err != nil {
			return utils.GenerateError("PasswordError", "Encrypt Password Error"+err.Error())
		}
		newPwd, err := utils.EncryptAES256([]byte(updateDB.Password), secretKey)
		if err != nil {
			return utils.GenerateError("EncryptPWDErr", err.Error())
		}
		updateDB.Salt = secretKey
		updateDB.Password = newPwd
		fmt.Println("修改密码成功")
	}
	updateDB.ID = source.ID
	updateDB.UpdateAt = time.Now()
	updateRes := db.Model(&source).Updates(updateDB)
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

func (t *Ticket) Create() error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	res := tx.Create(&t)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("TicketCreateErr", "create rows is not 1")
	}
	tx.Commit()
	return nil
}

// 不存在时创建记录，存在则更新 （根据SourceRef）
func (t *Ticket) LastAndCreateOrUpdate(cond Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	var tk Ticket
	// 检查是否存在该Issue对应的Ticket
	findRes := tx.Where(cond).Last(&tk)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return findRes.Error
	}
	if findRes.RowsAffected != 1 {
		// 直接创建
		createRes := tx.Create(&t)
		if createRes.Error != nil {
			tx.Rollback()
			return createRes.Error
		}
		if createRes.RowsAffected != 1 {
			tx.Rollback()
			return utils.GenerateError("TicketCreateErr", "Create row data count is not 1")
		}

	} else {
		// 存在记录，则更新状态
		updateRes := tx.Model(Ticket{}).Where(cond).Updates(Ticket{
			Status: common.EditedStatus, // 修改为Edited状态
		})
		if updateRes.Error != nil {
			tx.Rollback()
			return updateRes.Error
		}
		if updateRes.RowsAffected != 1 {
			tx.Rollback()
			return utils.GenerateError("TicketUpdateErr", "Update row data count is not 1")
		}
	}
	tx.Commit()
	return nil
}

// 获取查找结果
func (t *Ticket) FindOne(cond Ticket) (*Ticket, error) {
	var resultTicket Ticket
	dbConn := HaveSelfDB().GetConn()
	findRes := dbConn.Where(&cond).Last(&resultTicket)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return nil, utils.GenerateError("TicketErr", "the db record is not exist:"+findRes.Error.Error())
		}
		return nil, findRes.Error
	}
	if findRes.RowsAffected != 1 {
		return nil, utils.GenerateError("TicketErr", "rows is not 1")
	}
	return &resultTicket, nil
}

// 按照指定CondTicket进行更新
func (t *Ticket) Update(cond, updateTicket Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	// 根据ProjectID + IssueID作为条件，进行更新操作
	tk, err := t.FindOne(cond)
	if err != nil {
		return err
	}

	updateTicket.UID = t.UID
	// UpdateAt
	tx := dbConn.Begin()
	res := tx.Model(&tk).Updates(&updateTicket)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("TicketUpdateErr", "create rows is not 1")
	}
	tx.Commit()
	return nil
}

// 检查前置状态
func (t *Ticket) ValidateStatus(cond Ticket, targetStatus ...string) error {
	if len(targetStatus) == 0 {
		return nil
	}
	// 根据ProjectID + IssueID作为条件，进行更新操作
	tk, err := t.FindOne(cond)
	if err != nil {
		return err
	}
	// 检查前置Ticket状态
	if slices.Contains(targetStatus, tk.Status) {
		return nil
	}
	return utils.GenerateError("TicketStatusNotMatch", fmt.Sprintf("Ticket Status:%s is not match", tk.Status))
}

func (t *Ticket) ValidateAndUpdate(cond, update Ticket, targetStatus ...string) error {
	err := t.ValidateStatus(cond, targetStatus...)
	if err != nil {
		return err
	}
	return t.Update(cond, update)
}

// 封装
func (t *Ticket) ValidateAndUpdateStatus(cond Ticket, status string, targetStatus ...string) error {
	return t.ValidateAndUpdate(cond, Ticket{
		Status: status,
	})
}

// 获取Ticket Status的统计
func (t *Ticket) StatsCount() (map[string]int, error) {
	// 临时构建Ticket状态的结构体
	var statsCount struct {
		CreatedCount        int `gorm:""`
		ApprovalPassedCount int `gorm:""`
		ApprovalRejectCount int `gorm:""`
		ExcutePendingCount  int `gorm:""`
		PendingCount        int `gorm:""`
		CompletedCount      int `gorm:""`
		FailedCount         int `gorm:""`
		TotalCount          int `gorm:""`
	}
	// var resultTicket Ticket
	dbConn := HaveSelfDB().GetConn()
	res := dbConn.Model(&Ticket{}).Select(`
		SUM(CASE WHEN status = 'CREATED' THEN 1 ELSE 0 END) AS created_count,
		SUM(CASE WHEN status = 'PASSED' THEN 1 ELSE 0 END) AS passed_count,
		SUM(CASE WHEN status = 'REJECT' THEN 1 ELSE 0 END) AS reject_count,
		SUM(CASE WHEN status = 'EXCUTE_PENDING' THEN 1 ELSE 0 END) AS excute_pending_count,
		SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) AS pending_count,
		SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_count,
		SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed_count,
		COUNT(*) AS total_count
	`).Take(&statsCount)
	if res.Error != nil {
		return nil, res.Error
	}
	return map[string]int{
		"created":        statsCount.CreatedCount,
		"passed":         statsCount.ApprovalPassedCount,
		"reject":         statsCount.ApprovalRejectCount,
		"excute_pending": statsCount.ExcutePendingCount,
		"pending":        statsCount.PendingCount,
		"completed":      statsCount.CompletedCount,
		"failed":         statsCount.FailedCount,
		"total":          statsCount.TotalCount,
	}, nil
}

func (t *Ticket) GetSourceRef(busniessDomain string, snowKey int64, cond Ticket) string {
	switch t.Source {
	case "normal":
		return fmt.Sprintf("%s:user:%d:normal:%d", busniessDomain, cond.AuthorID, snowKey)
	case "gitlab":
		return fmt.Sprintf("%s:user:%d:gitlab:%d-%d", busniessDomain, cond.AuthorID, cond.ProjectID, cond.IssueID)
	default:
		return ""
	}
}
