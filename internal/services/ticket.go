package services

import (
	"fmt"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

// Ticket
type TicketService struct {
	DAO dbo.Ticket // 数据crud
}

func NewTicketService() *TicketService {
	return &TicketService{
		DAO: dbo.Ticket{},
	}
}

func (tk *TicketService) toORMData(data dto.TicketDTO) *dbo.Ticket {
	return &dbo.Ticket{
		UID:            data.UID,
		Status:         data.Status,
		Source:         data.Source,
		SourceRef:      data.SourceRef,
		BusinessRef:    data.BusinessRef,
		IdemoptencyKey: data.IdemoptencyKey,
		AuthorID:       data.AuthorID,
		ProjectID:      int(data.ProjectID),
		IssueID:        int(data.IssueIID),
		TaskID:         data.TaskID,
		TaskContent: dbo.TaskContent{
			Env:          data.TaskContent.Env,
			Service:      data.TaskContent.Service,
			Statement:    data.TaskContent.Statement,
			DBName:       data.TaskContent.DBName,
			LongTime:     data.TaskContent.LongTime,
			IsExport:     data.TaskContent.IsExport,
			IsSOAR:       data.TaskContent.IsSOAR,
			IsAiAnalysis: data.TaskContent.IsAiAnalysis,
		},
	}
}

func (tk *TicketService) toDTOData(data dbo.Ticket) *dto.TicketDTO {
	return &dto.TicketDTO{
		UID:            data.UID,
		Status:         data.Status,
		Source:         data.Source,
		SourceRef:      data.SourceRef,
		BusinessRef:    data.BusinessRef,
		IdemoptencyKey: data.IdemoptencyKey,
		AuthorID:       data.AuthorID,
		ProjectID:      uint(data.ProjectID),
		IssueIID:       uint(data.IssueID),
		TaskID:         data.TaskID,
		TaskContentID:  data.TaskContentID,
		TaskContent: dto.SQLTaskRequest{
			Env:          data.TaskContent.Env,
			Service:      data.TaskContent.Service,
			Statement:    data.TaskContent.Statement,
			DBName:       data.TaskContent.DBName,
			LongTime:     data.TaskContent.LongTime,
			IsExport:     data.TaskContent.IsExport,
			IsSOAR:       data.TaskContent.IsSOAR,
			IsAiAnalysis: data.TaskContent.IsAiAnalysis,
		},
	}
}

// 创建一个Ticket(返回SourceRef、IdemoptencyKey和Error)
func (tk *TicketService) Create(data dto.TicketDTO) (int64, error) {
	data.UID = utils.GenerateSnowKey()
	// 调用数据层进行创建
	ticketORM := tk.toORMData(data)
	//! 创建并关联任务内容
	return data.UID, tk.DAO.Create(ticketORM)
}

// 自动判断是否创建还是更新数据库记录
func (tk *TicketService) CreateOrUpdate(data dto.TicketDTO) (int64, error) {
	// 内建生成雪花ID
	data.UID = utils.GenerateSnowKey()

	condORM := tk.toORMData(dto.TicketDTO{
		SourceRef:      data.SourceRef,
		IdemoptencyKey: data.IdemoptencyKey,
	})
	dataORM := tk.toORMData(data)
	if !tk.DAO.IsExist(condORM) {
		// 创建
		return data.UID, tk.DAO.Create(dataORM)
	}
	err := tk.UpdateTaskContent(dto.TicketDTO{
		SourceRef:      data.SourceRef,
		IdemoptencyKey: data.IdemoptencyKey,
	}, data.TaskContent)
	if err != nil {
		return 0, err
	}
	return tk.DAO.Update(condORM, &dbo.Ticket{
		Status:    common.EditedStatus, // 修改为Edited状态
		ProjectID: int(data.ProjectID),
		IssueID:   int(data.IssueIID),
		AuthorID:  data.AuthorID,
	})
}

// 更新Ticket状态信息（会按照指定前置状态进行判断）
func (tk *TicketService) UpdateTicketStats(cond dto.TicketDTO, targetStats string, exceptStats ...string) error {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	return tk.DAO.ValidateAndUpdate(condORM, &dbo.Ticket{
		Status: targetStats,
	}, exceptStats...)
}

// 查找获取Ticket唯一标识
func (tk *TicketService) GetSourceRef(cond dto.TicketDTO) string {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	res, err := tk.DAO.FindOne(condORM)
	if err != nil {
		return ""
	}
	return res.SourceRef
}

// 查找获取Ticket唯一标识
func (tk *TicketService) GetUID(cond dto.TicketDTO) int64 {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	res, err := tk.DAO.FindOne(condORM)
	if err != nil {
		return 0
	}
	return res.UID
}

// 获取Tickets（可条件过滤）
func (tk *TicketService) Get(cond dto.TicketDTO, pagni *common.Pagniation) ([]dto.TicketDTO, error) {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	tksData, err := tk.DAO.Finds(condORM, pagni)
	if err != nil {
		return nil, err
	}
	fmt.Println(tksData, len(tksData), pagni.Page, pagni.PageSize)
	// 格式化
	DTOResults := make([]dto.TicketDTO, len(tksData))
	for k, result := range tksData {
		data := tk.toDTOData(result)
		// DTOResults = append(DTOResults, *data)
		DTOResults[k] = *data
	}
	return DTOResults, nil
}

// 仅API Task更新状态和任务内容
func (tk *TicketService) UpdateTaskContent(cond dto.TicketDTO, updateContent dto.SQLTaskRequest) error {
	// 更新Ticket信息
	expectStatus := []string{
		common.PreCheckSuccessStatus,
		common.DoubleCheckSuccessStatus,
		common.CompletedStatus,
		common.ApprovalPassedStatus,
		common.PreCheckFailedStatus,
		common.FailedStatus,
		common.DoubleCheckFailedStatus,
		common.ApprovalRejectStatus,
		common.EditedStatus,
	}
	condORM := tk.toORMData(cond)
	err := tk.DAO.ValidateStatus(condORM, expectStatus...)
	if err != nil {
		return err
	}
	dataORM := dbo.TaskContent{
		Env:          updateContent.Env,
		Service:      updateContent.Service,
		DBName:       updateContent.DBName,
		Statement:    updateContent.Statement,
		LongTime:     updateContent.LongTime,
		IsExport:     updateContent.IsExport,
		IsSOAR:       updateContent.IsSOAR,
		IsAiAnalysis: updateContent.IsAiAnalysis,
	}
	err = tk.DAO.SaveTaskContent(condORM, &dbo.Ticket{
		// BusinessRef: condORM.BusinessRef,
		Status:      common.EditedStatus,
		TaskContent: dataORM,
	})
	if err != nil {
		return err
	}
	return nil
}

// 关键词模糊搜索Ticket内容
func (tk *TicketService) Search(keyword string, pagni *common.Pagniation) ([]dto.TicketDTO, error) {
	res, err := tk.DAO.MatchAgainst([]string{
		"env", "service", "db_name", "statement",
	}, keyword, "IN BOOLEAN MODE", pagni)
	if err != nil {
		return nil, err
	}
	searchRes := make([]dto.TicketDTO, len(res))
	for key, result := range res {
		searchRes[key] = *tk.toDTOData(result)
	}
	return searchRes, nil
}

// 删除Ticket
func (tk *TicketService) Delete(cond dto.TicketDTO) error {
	condORM := tk.toORMData(cond)
	return tk.DAO.DeleteOne(condORM)
}

// 统计每个状态的Ticket数量
func (tk *TicketService) StatusCount() (map[string]int, error) {
	return tk.DAO.StatsCount()
}

// 检查事件payload
type FristCheckEventV2 struct {
	Ref      string // SourceRef 或 BusinessRef
	UserID   string
	Source   int
	TicketID int64
}
