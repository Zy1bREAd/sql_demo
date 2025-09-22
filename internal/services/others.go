package services

import (
	"errors"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"

	"gorm.io/gorm"
)

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
		//! 新增按照用户来查找
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
	}
}

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

// Ticket
type TicketService struct {
	DAO dbo.Ticket
}

func NewTicketService() TicketService {
	return TicketService{}
}

func (tk *TicketService) toORMData(dto dto.TicketStatusStatsDTO) *TicketService {
	return &TicketService{
		DAO: dbo.Ticket{},
	}
}

// 统计每个状态的Ticket数量
func (tk *TicketService) StatusCount() (map[string]int, error) {
	return tk.DAO.StatsCount()
}
