// 仅限SQL DEMO应用所使用的数据库操作
package apis

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var selfDB *SelfDatabase

type SelfDatabase struct {
	conn *gorm.DB
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
	config := getAppConfig()
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
	selfDB.autoMigrator()
	log.Println("DB migrator完成")
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
	return db.conn.AutoMigrate(&User{}, &QueryAuditLog{})
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

// 登录
func Login(email, pass string) (*UserResp, error) {
	// 使用该用户相同的salt，对用户密码进行加密验证，与数据库的加密密码进行对比
	var user User
	result := selfDB.conn.Where("email = ?", email).First(&user)
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

// 查询操作的日志审计
// 新增操作审计记录
func NewAuditRecord(userId uint, taskID string, statement, dbName string) error {
	tx := selfDB.conn.Begin()
	record := &QueryAuditLog{
		TaskID:       taskID,
		UserID:       userId,
		SQLStatement: statement,
		DBName:       dbName,
		// TimeStamp:    time.Now(),
	}
	result := selfDB.conn.Create(record)
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

func AllAuditRecords() error {
	queryRecords := &QueryAuditLog{}
	result := selfDB.conn.Find(queryRecords)
	if result.Error != nil {
		return result.Error
	}
	fmt.Println(queryRecords)
	return nil
}
