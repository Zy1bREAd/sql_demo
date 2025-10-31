package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"time"
)

// 临时结果集
type TempResultService struct {
	DAO       dbo.TempResult
	Operator  string // 操作者的用户ID
	isExport  bool
	isExpried bool
}

func NewTempResultService(userID string) *TempResultService {
	return &TempResultService{
		Operator: userID,
		DAO:      dbo.TempResult{},
	}
}

// 从数据库中获取结果集是否存在、是否过期？审计日志可选
// 通过UUkey -> Ticket ID -> 结果集
func (srv *TempResultService) GetData(ctx context.Context, cond dto.TempResultDTO, isAudit bool) (*core.SQLResultGroupV2, error) {
	condORM := srv.toORMData(cond)
	findRes, err := srv.DAO.FindOne(condORM)
	if err != nil {
		return nil, err
	}
	srv.isExport = findRes.IsExport()
	srv.isExpried = findRes.IsExpired()

	//! 查找并获取结果集
	c := core.GetKVCache()
	cKey := fmt.Sprintf("%s:%d", common.ResultPrefix, findRes.TicketID)
	val, exist := c.RistCache.Get(cKey)
	if !exist {
		// 不要什么都重做，这里需要手动执行重做。
		return nil, utils.GenerateError("CacheNotExist", "Result Data Cache is not exist")
	}
	resultVal, ok := val.(*core.SQLResultGroupV2)
	if !ok {
		return nil, utils.GenerateError("CacheNotMatch", "Result Data Cache Kind is not match")
	}
	if isAudit {
		// 审计日志
		auditLogSrv := NewAuditRecordService()
		auditLogSrv.Update(dto.AuditRecordDTO{
			TaskID: resultVal.GID,
		}, "RESULT_VIEW", srv.Operator, "")
	}
	return resultVal, nil
}

// 更新导出结果集的文件路径
func (srv *TempResultService) UpdateExportPath(cond dto.TempResultDTO, filePath, fileName string) error {
	condORM := srv.toORMData(cond)
	findRes, err := srv.DAO.FindOne(condORM)
	if err != nil {
		return err
	}
	// 更新查找出来的结果
	findRes.IsExported = true
	findRes.ExportFileName = fileName
	findRes.ExportPath = filePath
	findRes.ExportAt = time.Now()
	return srv.DAO.Update(condORM, findRes)
}

// 获取导出文件路径
func (srv *TempResultService) GetExportPath(taskID string) (path string, ok bool) {
	condORM := srv.toORMData(dto.TempResultDTO{
		TaskID: taskID,
	})
	findRes, err := srv.DAO.FindOne(condORM)
	if err != nil {
		return "", false
	}
	// 检查是否能够导出
	if findRes.IsExport() && !findRes.IsExpired() {
		return findRes.ExportPath, true
	}
	return "", false
}

func (srv *TempResultService) IsExpried() bool {
	return srv.isExpried
}

func (srv *TempResultService) IsExport() bool {
	return srv.isExport
}

func (srv *TempResultService) toORMData(data dto.TempResultDTO) *dbo.TempResult {
	return &dbo.TempResult{
		UUKey:         data.UUKey,
		TicketID:      data.TicketID,
		IsDeleted:     data.IsDeleted,
		IsAllowExport: data.IsAllowExport,
		IsExported:    data.IsExported,
		TaskID:        data.TaskID,
	}
}

// 创建新的临时结果集信息
func (srv *TempResultService) Insert(data dto.TempResultDTO, ddl int) error {
	dataORM := srv.toORMData(data)
	// 强制设置过期时间
	dataORM.ExpireAt = time.Now().Add(time.Duration(ddl) * time.Second)
	err := srv.DAO.Insert(dataORM)
	// 使用状态+过期时间双重控制（引入自动过期删除机制）
	time.AfterFunc(time.Duration(ddl)*time.Second, func() {
		condORM := srv.toORMData(dto.TempResultDTO{
			TicketID: data.TicketID,
			UUKey:    data.UUKey,
		})
		updateORM := srv.toORMData(dto.TempResultDTO{
			IsDeleted: true,
		})
		err := srv.DAO.Update(condORM, updateORM)
		if err != nil {
			utils.DebugPrint("CleanTempDataError", "delete temp result data is failed "+err.Error())
			return
		}
	})
	return err
}

type ExportOption func(*ExportResultService)

type ExportDetails struct {
	TaskID   string
	FilePath string
	FileName string
	Errrr    error
	// OnlyExportIdx int
	// IsOnly        bool // 仅导出
}

// ! 导出结果
type ExportResultService struct {
	DAO       dbo.TempResult
	Operator  string // 操作者的用户ID
	TaskID    string
	ResultIdx int
	IsOnly    bool // 仅导出
}

func NewExportResultService(opts ...ExportOption) *ExportResultService {
	export := &ExportResultService{}
	for _, opt := range opts {
		opt(export)
	}
	return export
}

func WithExportTaskID(taskID string) ExportOption {
	return func(as *ExportResultService) {
		as.TaskID = taskID
	}
}

func WithExportUserID(userID string) ExportOption {
	return func(as *ExportResultService) {
		as.Operator = userID
	}
}

func WithExportIsOnly(isOnly bool) ExportOption {
	return func(as *ExportResultService) {
		as.IsOnly = isOnly
	}
}

func WithExportResultIndex(index int) ExportOption {
	return func(as *ExportResultService) {
		as.ResultIdx = index
	}
}

// 准备【导出结果集】的事件
func (srv *ExportResultService) Prepare() (chan ExportDetails, error) {
	now := time.Now().Format("20060102150405")
	conf := conf.GetAppConf().GetBaseConfig()
	// 构建导出事件
	exportEvent := &ExportEvent{
		TaskID:        srv.TaskID,
		IsOnly:        srv.IsOnly,
		OnlyExportIdx: srv.ResultIdx,
		NotifyChannel: make(chan ExportDetails, 1),
	}
	// 确定完整的文件名（包含后缀）
	if srv.IsOnly {
		fileName := fmt.Sprintf("result_export_%s_%s", srv.TaskID, now)
		exportEvent.FileName = fileName + ".csv"
	} else {
		fileName := fmt.Sprintf("result_export_all_%s_%s", srv.TaskID, now)
		exportEvent.FileName = fileName + ".xlsx"
	}
	exportEvent.FilePath = conf.ExportEnv.FilePath + "/" + exportEvent.FileName

	// 插入【导出结果】审计日志
	jsonBytes, err := json.Marshal(&exportEvent)
	if err != nil {
		return exportEvent.NotifyChannel, err
	}
	auditLogSrv := NewAuditRecordService()
	err = auditLogSrv.Update(dto.AuditRecordDTO{
		TaskID:    srv.TaskID,
		EventType: "SQL_QUERY",
	}, "RESULT_EXPORT", srv.Operator, string(jsonBytes))
	if err != nil {
		return exportEvent.NotifyChannel, err
	}

	// 事件产生
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type:    "export_result",
		Payload: exportEvent,
		MetaData: event.EventMeta{
			Operator:  srv.Operator,
			Timestamp: time.Now().Format("20060102150405"),
		},
	})
	return exportEvent.NotifyChannel, nil
}

// 开始处理【导出结果集】事件
func (srv *ExportResultService) Export(ctx context.Context, ee *ExportEvent) error {
	exportDetail := ExportDetails{
		TaskID:   ee.TaskID,
		FilePath: ee.FilePath,
		FileName: ee.FileName,
	}

	// 获取结果集
	tempResSrv := NewTempResultService(srv.Operator)
	tempResult, err := tempResSrv.GetData(ctx, dto.TempResultDTO{
		TaskID: ee.TaskID,
	}, false)
	if err != nil {
		exportDetail.Errrr = err
		ee.NotifyChannel <- exportDetail
		return nil
	}

	// 构建并另存为文件
	conf := conf.GetAppConf().GetBaseConfig()
	if ee.IsOnly {
		// 仅导出
		csvRes := utils.CSVResult{
			BasePath: conf.ExportEnv.FilePath,
			FileName: ee.FileName,
			Data:     tempResult.Data[ee.OnlyExportIdx].Results,
		}
		err := csvRes.Convert()
		if err != nil {
			exportDetail.Errrr = err
		}
	} else {
		// 导出全部
		excelRes := utils.ExcelResult{
			BasePath: conf.ExportEnv.FilePath,
			FileName: ee.FileName,
		}
		err := excelRes.CreateFile()
		if err != nil {
			exportDetail.Errrr = err
		}
		for index, result := range tempResult.Data {
			excelRes.Data = result.Results
			excelRes.Index = index + 1
			err := excelRes.Convert()
			if err != nil {
				exportDetail.Errrr = err
			}
		}
	}

	// 文件路径写入数据库
	err = tempResSrv.UpdateExportPath(dto.TempResultDTO{
		TaskID: ee.TaskID,
	}, ee.FilePath, ee.FileName)
	if err != nil {
		exportDetail.Errrr = err
	}

	// 加入清理队列，等待清理（goroutine）
	time.AfterFunc(time.Second*time.Duration(conf.ExportEnv.HouseKeeping), func() {
		// HouseKeepQueue <- task
		ep := event.GetEventProducer()
		ep.Produce(event.Event{
			Type:    "file_housekeeping",
			Payload: ee,
		})
	})

	// 发送完成导出信号
	ee.NotifyChannel <- exportDetail
	return nil
}

// ! 下载逻辑
type DownloadService struct {
	Operator string // 操作者的用户ID
}

func NewDownloadService(userID string) *DownloadService {
	return &DownloadService{
		Operator: userID,
	}
}

// 下载导出文件
func (srv *DownloadService) Download(taskID string) (string, error) {
	tempResSrv := NewTempResultService(srv.Operator)
	filePath, ok := tempResSrv.GetExportPath(taskID)
	if !ok {
		return "", utils.GenerateError("ExportFailed", "Export File is not exist or expired")
	}

	if _, err := os.Stat(filePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", utils.GenerateError("FileNotExist", "Export File is not exist in system")
		}
		return "", err
	}

	//! 审计日志记录
	auditLogSrv := NewAuditRecordService()
	err := auditLogSrv.Update(dto.AuditRecordDTO{
		TaskID:    taskID,
		EventType: "RESULT_EXPORT",
	}, "RESULT_DOWNLOAD", srv.Operator, "")
	if err != nil {
		return "", err
	}
	return filePath, nil
}
