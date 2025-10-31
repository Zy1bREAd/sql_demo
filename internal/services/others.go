package services

import (
	"errors"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
	"time"

	"gorm.io/gorm"
)

// type AuditLogOption func(*AuditRecordService)

type AuditRecordService struct {
	DAO dbo.AuditRecordV2
}

func NewAuditRecordService() AuditRecordService {
	return AuditRecordService{
		DAO: dbo.AuditRecordV2{},
	}
}

func (audit *AuditRecordService) toORMData(dto dto.AuditRecordDTO) *dbo.AuditRecordV2 {
	return &dbo.AuditRecordV2{
		TaskID:    dto.TaskID,
		EventType: dto.EventType,
		StartTime: dto.StartTime,
		EndTime:   dto.EndTime,
		UserID:    dto.UserID,
		Payload:   dto.Payload,
		IssueID:   dto.IssueID,
		ProjectID: dto.ProjectID,
		TaskKind:  dto.TaskType,
		TicketID:  dto.TicketID,
	}
}

func (audit *AuditRecordService) toDTOData(orm dbo.AuditRecordV2) *dto.AuditRecordDTO {
	return &dto.AuditRecordDTO{
		TaskID:    orm.TaskID,
		EventType: orm.EventType,
		CreateAt:  orm.CreateAt.Format("2006-01-02 15:04:05"),
		TaskType:  orm.TaskKind,
		ProjectID: orm.ProjectID,
		IssueID:   orm.IssueID,
		UserName:  orm.User.Name,
		Payload:   orm.Payload,
		TicketID:  orm.TicketID,
	}
}

// 按照特定条件获取审计日志，具有分页器。
func (audit *AuditRecordService) Get(cond dto.AuditRecordDTO, pagni *common.Pagniation) ([]dto.AuditRecordDTO, error) {
	condORM := audit.toORMData(cond)
	// 如果按照用户名查找，需要判断该用户是否存在
	if condORM.User.Name != "" {
		dbConn := dbo.HaveSelfDB().GetConn()
		var user dbo.User
		res := dbConn.Where("name = ?", condORM.User.Name).Last(&user)
		if res.Error != nil {
			if errors.Is(res.Error, gorm.ErrRecordNotFound) {
				return nil, utils.GenerateError("UserNotFound", condORM.User.Name+" The user is not exist")
			}
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			return nil, utils.GenerateError("UserNotFound", condORM.User.Name+" The user is not exist")
		}
		condORM.UserID = user.ID
	}
	sqlResult, err := audit.DAO.Find(condORM, pagni)
	if err != nil {
		return nil, err
	}

	// 加入分页
	result := make([]dto.AuditRecordDTO, 0, pagni.PageSize)
	for _, record := range sqlResult {
		result = append(result, *audit.toDTOData(record))
	}
	return result, nil
}

// 插入新的审计日志
func (audit *AuditRecordService) Insert(data dto.AuditRecordDTO) error {
	dataORM := audit.toORMData(data)
	err := audit.DAO.InsertOne(dataORM)
	return err
}

// 【本质还是插入】查找此前的审计日志，并更新事件类型后插入新记录。
func (audit *AuditRecordService) Update(cond dto.AuditRecordDTO, eventKind, userID, payload string) error {
	condORM := audit.toORMData(cond)
	// 获取Issue详情(使用taskId和UserId来查找对应的issue)
	var auditRes dbo.AuditRecordV2
	dbConn := dbo.HaveSelfDB().GetConn()
	res := dbConn.Where(&condORM).Last(&auditRes)
	if res.Error != nil {
		return utils.GenerateError("AuditRecordError", res.Error.Error())
	}
	if res.RowsAffected != 1 {
		return utils.GenerateError("AuditRecordError", "rows is zero")
	}
	// 日志审计插入v3 （修改用户ID、修改事件类型）
	auditRes.ID = 0
	auditRes.CreateAt = time.Now()
	auditRes.UserID = userID
	auditRes.EventType = eventKind
	if payload != "" {
		auditRes.Payload = payload
	}
	err := audit.DAO.InsertOne(&auditRes)
	return err
}

// ! 导出事件
type ExportEvent struct {
	NotifyChannel chan ExportDetails `json:"-"`
	TaskID        string
	FilePath      string
	FileName      string
	OnlyExportIdx int
	IsOnly        bool // 仅导出
}
