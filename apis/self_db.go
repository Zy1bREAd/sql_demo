// 仅限SQL DEMO应用所使用的数据库操作
package apis

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var selfDB *SelfDatabase

type SelfDatabase struct {
	conn *gorm.DB
}

func connect(dsn string) error {
	if selfDB == nil {
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return GenerateError("DB Connect Failed", "sql demo self db unable to connect")
		}
		selfDB = &SelfDatabase{
			conn: db,
		}
		return nil
	}
	// 健康检查决定连接成败
	return selfDB.healthCheck()
}

func InitSelfDB(dsn string) *SelfDatabase {
	err := connect(dsn)
	if err != nil {
		panic(err)
	}
	// 迁移表
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
		return GenerateError("Migrator Failed", "db is not init")
	}
	// 表多的话要以注册的方式注册进来，避免手动一个个输入
	return db.conn.AutoMigrate(&User{}, &QueryAuditLog{})
}

// 创建用户逻辑
func CreateUser(name, pass, email string) error {
	// 事务开启
	tx := selfDB.conn.Begin()
	// 创建User(避免明文传入)
	salt := GenerateSalt()
	user := &User{
		Name:     name,
		Email:    email,
		Password: EncryptWithSaltMd5(salt, pass),
		CreateAt: time.Now(),
	}
	fmt.Println(user)
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
	if ok := ValidateValueWithMd5(pass, user.Password); ok {
		// 登录成功
		// 过滤隐私关键字段（将结构体映射成专用响应结构体）
		userResp := user.ToUserResp()
		return &userResp, nil
	}

	return nil, GenerateError("LoginFailed", "the user account or password is incorrect")
}

// 查询操作的日志审计
