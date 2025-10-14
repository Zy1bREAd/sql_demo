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
	return db.conn.AutoMigrate(&User{}, &TempResult{}, &AuditRecordV2{}, &QueryDataBase{}, &QueryEnv{}, &Ticket{}, &TaskContent{})
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
	tempData := TempResult{
		UUKey:         uukey,
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
		res := selfDB.conn.Model(&TempResult{}).Where("uid = ?", uukey).Where("ticket_id = ?", ticketID).Update("is_deleted", 1)
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

func AllowResultExport(taskId string) bool {
	var tempData TempResult
	res := selfDB.conn.Where("task_id = ?", taskId).First(&tempData)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false
		}
		return false
	}
	if tempData.IsDeleted || time.Now().After(tempData.ExpireAt) {
		return false
	}
	return tempData.IsAllowExport
}

// 审计日志：插入接口
func (v2 *AuditRecordV2) InsertOne(data *AuditRecordV2) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	// 避免携带默认值插入污染导出相关信息
	result := tx.Create(&data)
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

// 按照Cond条件查找
func (v2 *AuditRecordV2) Find(cond *AuditRecordV2, pagni *common.Pagniation) ([]AuditRecordV2, error) {
	var records []AuditRecordV2
	dbConn := HaveSelfDB().GetConn()
	// 抽象基础查询链
	tx := dbConn.Model(&AuditRecordV2{}).Preload("User").Where(&cond)
	// 判断时间范围筛选条件是否有效
	if cond.StartTime != "" && cond.EndTime != "" {
		//! 没有判断endtime小于starttime的情况
		tx = tx.Where("create_at BETWEEN ? AND ?", cond.StartTime, cond.EndTime)
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

func (source *QueryDataBase) CreateOne(data *QueryDataBase) error {
	db := HaveSelfDB().GetConn()

	dbIst := data.Service
	envId := data.EnvID
	// 不存在则创建，反之不创建
	findRes := db.Where("env_id = ? AND service = ?", envId, dbIst).First(&source)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return utils.GenerateError("FindError", findRes.Error.Error())
	}
	if findRes.RowsAffected == 1 {
		return utils.GenerateError("CreateError", "the db instance is exist")
	}
	tx := db.Begin()
	insertRes := db.Create(&data)
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

func (env *QueryEnv) CreateOne(data *QueryEnv) error {
	db := HaveSelfDB().GetConn()

	// 不存在则创建，反之不创建
	findRes := db.Where("name = ?", data.Name).First(&env)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return utils.GenerateError("CreateError", findRes.Error.Error())
	}
	if findRes.RowsAffected > 0 {
		return utils.GenerateError("CreateError", "the env is exist")
	}
	tx := db.Begin()
	insertRes := db.Create(&data)
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
func (env *QueryEnv) Find(cond *QueryEnv, pagni *common.Pagniation) ([]QueryEnv, error) {
	var envList []QueryEnv
	dbConn := HaveSelfDB().GetConn()
	// 构造基础查询链
	tx := dbConn.Model(&QueryEnv{}).Where(&cond)
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
		return nil, utils.GenerateError("FindEnvError", findRes.Error.Error())
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

func (source *QueryDataBase) GetEnvID(envName string) (uint, error) {
	db := HaveSelfDB().GetConn()
	var envResult QueryEnv
	res := db.Model(&QueryEnv{}).Where("name = ?", envName).Last(&envResult)
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected != 1 {
		return 0, errors.New("env Record is not exist")
	}
	return envResult.ID, nil
}

// 查找全部
func (source *QueryDataBase) Find(cond *QueryDataBase, pagni *common.Pagniation) ([]QueryDataBase, error) {
	var dbList []QueryDataBase
	db := HaveSelfDB().GetConn()
	// 构造基础查询链
	tx := db.Model(&QueryDataBase{}).Preload("EnvForKey").Where(&cond)
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
	findRes := tx.Debug().Find(&dbList)
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

// 通过条件更新单个结果
func (env *QueryEnv) UpdateOne(cond, updateEnv *QueryEnv) error {
	db := HaveSelfDB().GetConn()
	opera := db.Where(&cond).Last(&env)
	if opera.Error != nil {
		// 不存在时无法更新
		if errors.Is(opera.Error, gorm.ErrRecordNotFound) {
			return utils.GenerateError("UpdateFailed", "Env is not exist,"+opera.Error.Error())
		}
		return utils.GenerateError("UpdateFailed", opera.Error.Error())
	}
	// 事务开启
	tx := db.Begin()
	updateRes := tx.Model(&QueryEnv{}).Where(&cond).Updates(updateEnv)
	if updateRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("UpdateFailed", opera.Error.Error())
	}
	if updateRes.RowsAffected != 1 {
		return utils.GenerateError("UpdateFailed", "Update rows is not 1")
	}
	tx.Commit()
	return nil
}

// 更新单个数据源
func (source *QueryDataBase) UpdateOne(cond, updateDB *QueryDataBase) error {
	db := HaveSelfDB().GetConn()
	// 要事先确定外键ID，确保唯一性。
	findRes := db.Where(&cond).First(&source)
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

	// updateDB.ID = source.ID
	updateDB.UpdateAt = time.Now()
	updateRes := tx.Model(&QueryDataBase{}).Where(QueryDataBase{
		ID: source.ID,
	}).Updates(&updateDB)
	if updateRes.Error != nil {
		tx.Rollback()
		return utils.GenerateError("UpdateError", updateRes.Error.Error())
	}
	tx.Commit()
	return nil
}

// 根据条件进行删除
func (env *QueryEnv) DeleteOne(cond *QueryEnv) error {
	db := HaveSelfDB().GetConn()
	tx := db.Begin()
	res := tx.Where(&cond).Delete(&env)
	if res.Error != nil {
		tx.Rollback()
		return utils.GenerateError("DeleteError", res.Error.Error())
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("DeleteError", "delete row is error")
	}
	tx.Commit()
	return nil
}

// 按照结构体进行删除
func (qdb *QueryDataBase) DeleteOne(cond *QueryDataBase) error {
	db := HaveSelfDB().GetConn()
	tx := db.Begin()
	res := tx.Where(&cond).Delete(&cond)
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

// 通过结构体对象直接使用
func (t *Ticket) Create(data *Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	res := tx.Create(&data)
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

// 检查是否存在该Ticket记录
func (t *Ticket) IsExist(cond *Ticket) bool {
	dbConn := HaveSelfDB().GetConn()
	var findTicket Ticket
	// 检查是否存在该Issue对应的Ticket
	findRes := dbConn.Where(&cond).Last(&findTicket)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		return false
	}
	if findRes.RowsAffected != 1 {
		return false
	}
	return true
}

// 不存在时创建记录，存在则更新 （根据SourceRef）
func (t *Ticket) CreateOrUpdate(cond, data *Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	var findTicket Ticket
	// 检查是否存在该Issue对应的Ticket
	findRes := tx.Where(&cond).Last(&findTicket)
	if findRes.Error != nil && !errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return findRes.Error
	}
	if findRes.RowsAffected != 1 {
		// 直接创建
		createRes := tx.Create(&data)
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
		updateRes := tx.Model(Ticket{}).Where(&cond).Updates(Ticket{
			Status:    common.EditedStatus, // 修改为Edited状态
			ProjectID: data.ProjectID,
			IssueID:   data.IssueID,
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

// 获取查找结果(关联加载TaskContent和User模型)
func (t *Ticket) FindOne(cond *Ticket) (*Ticket, error) {
	var resultTicket Ticket
	dbConn := HaveSelfDB().GetConn()
	findRes := dbConn.Preload("TaskContent").Preload("UserForKey").Where(&cond).Last(&resultTicket)
	if findRes.Error != nil {
		if errors.Is(findRes.Error, gorm.ErrRecordNotFound) {
			return nil, utils.GenerateError("TicketNotExist", findRes.Error.Error())
		}
		return nil, findRes.Error
	}
	if findRes.RowsAffected != 1 {
		return nil, utils.GenerateError("TicketErr", "rows is not 1")
	}
	return &resultTicket, nil
}

// !查询符合条件的所有Tickets
func (t *Ticket) Finds(cond *Ticket, pagni *common.Pagniation) ([]Ticket, error) {
	var tks []Ticket
	dbConn := HaveSelfDB().GetConn()
	// 构造基础查询链
	tx := dbConn.Model(&Ticket{}).Where(&cond).Preload("TaskContent").Preload("UserForKey")
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, err
	}
	//! 防止无效分页请求(前提是分页器有数据，像初始化时分页器无数据则无需判断)
	if pagni.Page != 0 && pagni.PageSize != 0 {
		if (int(total)/pagni.PageSize)+1 <= pagni.Page {
			return nil, utils.GenerateError("PageErr", "Page must be too big")
		}
		tx = tx.Offset(pagni.Offset).Limit(pagni.PageSize)
	}
	pagni.SetTotal(int(total))
	findRes := tx.Find(&tks)
	if findRes.Error != nil {
		return nil, utils.GenerateError("TicketFindErr", findRes.Error.Error())
	}
	// debug
	for _, v := range tks {
		fmt.Println("debug piring2 v.TaskContent", v.TaskContent)
	}
	return tks, nil
}

// 按照指定CondTicket进行更新 (返回更新后的TicketID)
func (t *Ticket) Update(cond, updateTicket *Ticket) (int64, error) {
	dbConn := HaveSelfDB().GetConn()
	// 根据ProjectID + IssueID作为条件，进行更新操作
	tk, err := t.FindOne(cond)
	if err != nil {
		return 0, err
	}

	updateTicket.UID = tk.UID // ! 重大改动，修改为查找的TicketID

	tx := dbConn.Begin()
	res := tx.Model(&tk).Updates(&updateTicket)
	if res.Error != nil {
		tx.Rollback()
		return 0, res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return 0, utils.GenerateError("TicketUpdateErr", "create rows is not 1")
	}
	tx.Commit()
	return tk.UID, nil
}

func (t *Ticket) SaveTaskContent(cond, data *Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	tk, err := t.FindOne(cond)
	if err != nil {
		return err
	}
	// 更新被查找出来的ticket data
	t.UID = tk.UID //! 传递修改UID后续再次预检需要使用
	data.TaskContent.ID = tk.TaskContent.ID
	data.TaskContent.CreatedAt = tk.TaskContent.CreatedAt
	tk.TaskContent = data.TaskContent
	tk.Status = data.Status

	tx := dbConn.Begin()
	if err = tx.Save(&tk.TaskContent).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err = tx.Save(&tk).Error; err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func (t *Ticket) DeleteOne(cond *Ticket) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	res := tx.Delete(&cond)
	if res.Error != nil {
		tx.Rollback()
		return utils.GenerateError("DeleteError", res.Error.Error())
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("DeleteError", "delete row is error")
	}
	tx.Commit()
	return nil
}

func (t *Ticket) UpdateByFind(cond, updateTicket *Ticket) error {
	_, err := t.Update(cond, updateTicket)
	return err
}

// 检查前置状态
func (t *Ticket) ValidateStatus(cond *Ticket, targetStatus ...string) error {
	if len(targetStatus) == 0 {
		return nil
	}
	tk, err := t.FindOne(cond)
	if err != nil {
		return err
	}
	// 检查前置Ticket状态
	if slices.Contains(targetStatus, tk.Status) {
		return nil
	}
	// TODO: 修改正确的错误描述
	return utils.GenerateError("TicketStatusNotMatch", fmt.Sprintf("Ticket Status:%s is not match %s", tk.Status, targetStatus))
}

func (t *Ticket) ValidateAndUpdate(cond, update *Ticket, targetStatus ...string) error {
	err := t.ValidateStatus(cond, targetStatus...)
	if err != nil {
		return err
	}
	return t.UpdateByFind(cond, update)
}

// 封装
func (t *Ticket) ValidateAndUpdateStatus(cond *Ticket, status string, targetStatus ...string) error {
	return t.ValidateAndUpdate(cond, &Ticket{
		Status: status,
	}, targetStatus...)
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

// 查找数据
func (tmp *TempResult) FindOne(cond *TempResult) (*TempResult, error) {
	var findRes TempResult
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Where(&cond).Last(&findRes)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, utils.GenerateError("RowsError", "RowsAffected is not match")
	}
	return &findRes, nil
}

// 检查是否过期
func (tmp *TempResult) IsExpired() bool {
	if tmp.IsDeleted || time.Now().After(tmp.ExpireAt) {
		return true
	}
	return false
}

// 检查是否过期
func (tmp *TempResult) IsExport() bool {
	if !tmp.IsAllowExport || time.Now().After(tmp.ExpireAt) {
		return false
	}
	return true
}

func (tmp *TempResult) FindByUUKey(uuKey string) (*TempResult, error) {
	findRes, err := tmp.FindOne(&TempResult{
		UUKey: uuKey,
	})
	if err != nil {
		return nil, err
	}
	return findRes, nil
}

// 数据库创建临时结果集数据
func (tmp *TempResult) Insert(data *TempResult) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	res := tx.Create(&data)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("CreateError", "tempresult data is insert failed")
	}
	tx.Commit()
	return nil
}

// 批量更新
func (tmp *TempResult) Update(cond, data *TempResult) error {
	dbConn := HaveSelfDB().GetConn()
	tx := dbConn.Begin()
	res := tx.Model(&TempResult{}).Where(&cond).Updates(&data)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return utils.GenerateError("CreateError", "tempresult data is update failed")
	}
	tx.Commit()
	return nil
}
