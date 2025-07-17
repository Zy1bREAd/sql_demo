// 仅限SQL DEMO应用所使用的数据库操作
package apis

import (
	"errors"
	"fmt"
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

func connect(dsn string, maxIdle, maxConn int) error {
	if selfDB == nil {
		gdb, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return GenerateError("DB Connect Failed", "sql demo self db unable to connect")
		}
		dbPool, err := gdb.DB()
		if err != nil {
			return GenerateError("DB Connect Failed", "db conn pool init failed")
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

func InitSelfDB() *SelfDatabase {
	config := GetAppConfig()
	for driver, conf := range config.DBEnv {
		// 判断不同数据库驱动选择不同的连接方式
		switch {
		case strings.ToLower(driver) == "mysql":
			err := connect(conf.DSN, conf.IdleTime, conf.MaxConn)
			if err != nil {
				panic(GenerateError("????", err.Error()))
			}
		default:
			panic(GenerateError("DB Driver Not Found", "driver not found"))
		}
	}

	// auto迁移表
	err := selfDB.autoMigrator()
	if err != nil {
		newErr := GenerateError("AutoMigratorFailed", err.Error())
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
		return GenerateError("Migrator Failed", "self db is not init")
	}
	// 表多的话要以注册的方式注册进来，避免手动一个个输入
	return db.conn.AutoMigrate(&User{}, &AuditRecord{}, &TempResultMap{}, &AuditRecordV2{})
}

// 创建用户逻辑
func CreateUser(name, pass, email string) error {
	// 事务开启
	var isExistUser User
	result := selfDB.conn.Where("email = ?", email).First(&isExistUser)
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// 注册用户：用户是否被注册
		return GenerateError("UserExist", "user has been registerd")
	}
	tx := selfDB.conn.Begin()
	// 创建User(避免明文传入)
	salt := GenerateSalt()
	user := &User{
		Name:     name,
		Email:    email,
		Password: EncryptWithSaltMd5(salt, pass),
		CreateAt: time.Now(),
	}
	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		errMsg := fmt.Sprintln("create user is failed, ", err.Error())
		return GenerateError("Insert Failed", errMsg)
	}

	//提交事务
	tx.Commit()
	return nil
}

// 登录(Basic)
func BasicLogin(email, pass string) (*UserResp, error) {
	// 使用该用户相同的salt，对用户密码进行加密验证，与数据库的加密密码进行对比
	var user User
	result := selfDB.conn.Where("email = ?", email).Where("user_type = ?", 0).First(&user)
	if result.Error != nil {
		// 判断记录是否不存在
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			errMsg := fmt.Sprintf("the account=%s is not exist", email)
			return nil, GenerateError("UserNotExist", errMsg)
		}
		return nil, result.Error
	}
	// 校验用户密码
	if ok := ValidateValueWithMd5(pass, user.Password); !ok {
		return nil, GenerateError("LoginFailed", "the user account or password is incorrect")
	}
	// 登录成功
	// 过滤隐私关键字段（将结构体映射成专用响应结构体）
	userResp := user.ToUserResp()
	return &userResp, nil
}

// 登录（SSO gitlab）,最终返回用户id
func SSOLogin(username, email string) (uint, error) {
	var ssoUser User
	result := selfDB.conn.Where("name = ?", username).Where("email = ?", email).Where("user_type = ?", 2).First(&ssoUser)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// 首次注册进入DB
			newSSOUser := &User{
				Name:     username,
				Email:    email,
				UserType: 2,
				CreateAt: time.Now(),
			}
			tx := selfDB.conn.Begin()
			if err := tx.Create(newSSOUser).Error; err != nil {
				tx.Rollback()
				errMsg := fmt.Sprintln("create sso user is failed, ", err.Error())
				return 0, GenerateError("SSOUserError", errMsg)
			}
			//提交事务
			tx.Commit()
		}
		return 0, result.Error
	}
	// 用户登录日志插槽
	return ssoUser.ID, nil
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
		return GenerateError("InsertAuditRecordError", "insert a query record failed")
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
		return GenerateError("RecordError", "update a query record failed")
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
// 		return GenerateError("RecordError", "update a query record failed")
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
		DebugPrint("AuditRecordError", res.Error.Error())
		return nil, errors.New("<DBQueryFailed>" + res.Error.Error())
	}
	if res.RowsAffected == 0 {
		DebugPrint("AuditRecordError", "audit records is null")
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
			DebugPrint("DelTempResultError", "delete temp result link is failed "+res.Error.Error())
			return
		}
		if res.RowsAffected == 0 {
			DebugPrint("DelTempResultError", "RowsAffected is zero")
			return
		}

	})
	return nil
}

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

func GetUserId(gUserId uint) uint {
	var u User
	res := selfDB.conn.Where("git_lab_identity = ?", gUserId).First(&u)
	if res.Error != nil {
		DebugPrint("DBAPIError", "get user id is failed")
		return 0
	}
	return u.ID
}
