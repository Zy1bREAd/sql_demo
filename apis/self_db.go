// 仅限SQL DEMO应用所使用的数据库操作
package apis

import (
	"fmt"
	"log"

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
	closer, _ := db.conn.DB()
	closer.Close()
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

// 用户的逻辑
func CreateUser(name, pass, email string) error {
	// 事务开启
	tx := selfDB.conn.Begin()
	// 创建User(避免明文传入)
	user := &User{
		Name:     name,
		Email:    email,
		Password: EncryptWithMd5(pass),
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

// 查询操作的日志审计
