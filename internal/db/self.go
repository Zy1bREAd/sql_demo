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
	return db.conn.AutoMigrate(&User{}, &AuditRecord{}, &TempResultMap{}, &AuditRecordV2{})
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
func (usr *User) BasicLogin(inputPwd string) (*UserResp, error) {
	// 使用该用户相同的salt，对用户密码进行加密验证，与数据库的加密密码进行对比
	dbConn := HaveSelfDB().GetConn()
	result := dbConn.Where("email = ?", usr.Email).Where("user_type = ?", 0).First(&usr)
	if result.Error != nil {
		// 判断记录是否不存在
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			errMsg := fmt.Sprintf("the account=%s is not exist", usr.Email)
			return nil, utils.GenerateError("UserNotExist", errMsg)
		}
		return nil, result.Error
	}
	// 校验用户密码
	if ok := utils.ValidateValueWithMd5(inputPwd, usr.Password); !ok {
		return nil, utils.GenerateError("LoginFailed", "the user account or password is incorrect")
	}
	// 登录成功
	// 过滤隐私关键字段（将结构体映射成专用响应结构体）
	userResp := usr.ToUserResp()
	return &userResp, nil
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

// 查询操作的日志审计
// 新增操作审计记录
func (re *AuditRecord) InsertOne() error {
	tx := selfDB.conn.Begin()
	// 避免携带默认值插入污染导出相关信息
	result := selfDB.conn.Omit("IsExported", "ExportTime").Create(&re)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("InsertAuditRecordError", "insert a query record failed")
	}
	tx.Commit()

	return nil
}

func (re *AuditRecord) UpdateExport() error {
	tx := selfDB.conn.Begin()
	result := selfDB.conn.Where("task_id = ?", re.TaskID).Where("user_id = ?", re.UserID).Updates(&re)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("RecordError", "update a query record failed")
	}
	tx.Commit()
	return nil
}

// func UpdateExportAuditRecord(record *AuditRecord) error {
// 	tx := selfDB.conn.Begin()
// 	result := selfDB.conn.Where("task_id = ?", record.TaskID).Where("user_id = ?", record.UserID).Updates(&record)
// 	if result.Error != nil {
// 		tx.Rollback()
// 		return result.Error
// 	}
// 	if result.RowsAffected != 1 {
// 		tx.Rollback()
// 		return utils.GenerateError("RecordError", "update a query record failed")
// 	}
// 	tx.Commit()
// 	return nil
// }

func AllAuditRecords() error {
	auditRecords := AuditRecord{}
	result := selfDB.conn.Find(&auditRecords)
	if result.Error != nil {
		return result.Error
	}
	return nil
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
	auditRecords := []AuditRecord{}
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
	for _, record := range auditRecords {
		userRecords = append(userRecords, UserAuditRecord{
			Env:          record.Env,
			DBName:       record.DBName,
			SQLStatement: record.SQLStatement,
			ExcuteTime:   record.TimeStamp,
		})
	}
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
