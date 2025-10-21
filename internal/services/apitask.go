package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"time"
)

type ReExcute struct {
	IsReExcute bool
	Deadline   int
	Fn         func()
}

// ! Task服务接口
type TaskServicer interface {
	UpdateTicketStats(targetStats string, exceptStats ...string) error
	ReCheck()
}

type APIOption func(*APITaskService)

// API调用
type APITaskService struct {
	BusinessRef string
	UID         int64
	UserID      uint
}

func NewAPITaskService(opts ...APIOption) *APITaskService {
	apiTask := &APITaskService{}
	for _, opt := range opts {
		opt(apiTask)
	}
	return apiTask
}

func WithAPITaskUserID(userID string) APIOption {
	return func(as *APITaskService) {
		as.UserID = utils.StrToUint(userID)
	}
}

func WithAPITaskTaskUID(uid int64) APIOption {
	return func(as *APITaskService) {
		as.UID = uid
	}
}

func WithAPITaskBusinessRef(businessRef string) APIOption {
	return func(as *APITaskService) {
		as.BusinessRef = businessRef
	}
}

// API调用创建SQLTask和Ticket
func (srv *APITaskService) Create(data dto.SQLTaskRequest) (*dto.TicketDTO, error) {
	// 创建Ticket(需要根据客户端来主动构造business_ref)信息
	tk := NewTicketService()
	busniessDomain := "sql-task"
	UUID := utils.GenerateUUIDKey()
	userID := srv.UserID
	// {业务域}:{来源}:{UUID}:user:{主体id}
	sourceRef := fmt.Sprintf("%s:%s:%s:user:%d", busniessDomain, "api", UUID, userID)
	// 仅UUID
	businessRef := UUID
	// {动作}:{UUID}
	IdempKey := fmt.Sprintf("%s:%s", "submit", UUID)

	tkData := dto.TicketDTO{
		Status:         common.CreatedStatus,
		Source:         common.APISourceFlag,
		SourceRef:      sourceRef,
		BusinessRef:    businessRef,
		IdemoptencyKey: IdempKey,
		AuthorID:       userID,
		TaskContent:    data,
	}
	tkID, err := tk.Create(tkData)
	if err != nil {
		return nil, err
	}
	tkData.UID = tkID
	// !临时存储(不能使用UID，因为每次UID都会变动，需要使用businessRef来标识一组完整事件)
	core.APITaskBodyMap.Set(tkData.UID, data, common.DefaultCacheMapDDL, common.APITaskBodyMapCleanFlag)

	// 创建SQLTask的审计日志
	taskBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	auditLogSrv := NewAuditRecordService()
	err = auditLogSrv.Insert(dto.AuditRecordDTO{
		UserID:    userID,
		Payload:   string(taskBody),
		TaskType:  common.APITaskType,
		EventType: "TASK_CREATED",
		TicketID:  tkID,
	})
	if err != nil {
		return nil, err
	}

	// 生产事件(预检阶段)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID: tkData.UID,
			UserID:   userID,
			Source:   common.APISourceFlag,
			Ref:      tkData.BusinessRef,
		},
		MetaData: event.EventMeta{
			Source:    "api",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
			// ! 额外增加追溯唯一标识
			TraceID: businessRef,
		},
	})

	return &tkData, nil
}

// 更新Ticket状态以及Task Contente
func (srv *APITaskService) Update(data dto.SQLTaskRequest) error {
	tk := NewTicketService()
	tkData := dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}
	err := tk.UpdateTaskContent(tkData, data)
	if err != nil {
		return err
	}
	tkID := srv.getTicketID()
	// 创建SQLTask的审计日志
	taskBody, err := json.Marshal(data)
	if err != nil {
		return err
	}
	auditLogSrv := NewAuditRecordService()
	err = auditLogSrv.Insert(dto.AuditRecordDTO{
		UserID:    srv.UserID,
		Payload:   string(taskBody),
		TaskType:  common.APITaskType,
		EventType: "TASK_EDITED",
		TicketID:  tkID,
	})
	if err != nil {
		return err
	}

	// 生产事件(编辑-预检阶段)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID: tkID,
			UserID:   srv.UserID,
			Source:   common.APISourceFlag,
			Ref:      srv.BusinessRef,
		},
		MetaData: event.EventMeta{
			Source:    "api",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
			// ! 额外增加追溯唯一标识
			TraceID: srv.BusinessRef,
		},
	})

	return nil
}

// 更新Ticket状态以及Task Contente
func (srv *APITaskService) Delete() error {
	tk := NewTicketService()
	tkData := dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}
	err := tk.Delete(tkData)
	if err != nil {
		return err
	}

	return nil
}

// 关键词查找还是全部获取数据
func (srv *APITaskService) Get(keyword string, pagni *common.Pagniation) ([]dto.TicketDTO, error) {
	tk := NewTicketService()
	if keyword == "" {
		return tk.Get(dto.TicketDTO{}, pagni)
	}
	return tk.Search(keyword, pagni)
}

// func (srv *APITaskService) Search(keyword string, pagni *common.Pagniation) ([]dto.TicketDTO, error) {
// 	tk := NewTicketService()
// 	return tk.Search(keyword)
// }

func (srv *APITaskService) getTicketID() int64 {
	tk := NewTicketService()
	tkData := dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}
	return tk.GetUID(tkData)
}

// ! 存储预检任务信息
func (srv *APITaskService) SaveCheckData(ctx context.Context, preCheckVal *core.PreCheckResultGroup) error {
	core.CheckTaskMap.Set(srv.UID, preCheckVal, common.DefaultCacheMapDDL, common.CheckTaskMapCleanFlag)
	return nil
}

// 获取预检数据
func (srv *APITaskService) GetCheckData() (*core.PreCheckResultGroup, error) {
	//获取雪花ID
	tkID := srv.getTicketID()
	srv.UID = tkID
	val, exist := core.CheckTaskMap.Get(tkID)
	if !exist {
		return nil, utils.GenerateError("CheckDataError", "Check Data is not exist")
	}
	preCheckVal, ok := val.(*core.PreCheckResultGroup)
	if !ok {
		return nil, utils.GenerateError("CheckDataError", "Check Data assert failed")
	}
	return preCheckVal, nil
}

// 获取结果集数据
func (srv *APITaskService) GetResultData() (*core.SQLResultGroupV2, error) {
	//获取雪花ID
	tkID := srv.getTicketID()
	srv.UID = tkID
	val, exist := core.ResultMap.Get(tkID)
	if !exist {
		return nil, utils.GenerateError("ResultDataError", "SQLTask Result Data is not exist")
	}
	resultVal, ok := val.(*core.SQLResultGroupV2)
	if !ok {
		return nil, utils.GenerateError("ResultDataError", "SQLTask Result Data assert failed")
	}

	if resultVal.Errrr != nil {
		return nil, resultVal.Errrr
	}

	// 审计日志
	auditLogSrv := NewAuditRecordService()
	auditLogSrv.Update(dto.AuditRecordDTO{
		TaskID: resultVal.GID,
	}, "RESULT_VIEW", srv.UserID, "")
	return resultVal, nil
}

// 审批通过、驳回和上线
func (srv *APITaskService) ActionHandle(ctx context.Context, status int) error {
	switch status {
	case common.ApprovalActionFlag:
		return srv.approval()
	case common.RejectActionFlag:
		return srv.reject()
	case common.OnlineActionFlag:
		return srv.online(ctx)
	default:
		return errors.New("unknown Action")
	}
}

func (srv *APITaskService) approval() error {
	tk := NewTicketService()
	expectStatus := []string{
		common.PreCheckSuccessStatus,
		common.CompletedStatus,
		common.ApprovalPassedStatus,
	}
	err := tk.UpdateTicketStats(
		dto.TicketDTO{
			BusinessRef: srv.BusinessRef,
		},
		common.ApprovalPassedStatus, expectStatus...)
	return err
}

func (srv *APITaskService) reject() error {
	tk := NewTicketService()
	expectStatus := []string{
		common.PreCheckSuccessStatus,
		common.PreCheckFailedStatus,
		common.ApprovalPassedStatus,
	}
	err := tk.UpdateTicketStats(
		dto.TicketDTO{
			BusinessRef: srv.BusinessRef,
		},
		common.ApprovalRejectStatus, expectStatus...)
	return err
}

func (srv *APITaskService) online(ctx context.Context) error {
	ep := event.GetEventProducer()
	tk := NewTicketService()
	// 利用business_ref间接获取雪花ID来获取其他数据
	tkID := srv.getTicketID()
	srv.UID = tkID

	// 获取Task Body数据v2 重做机制版
	taskBodyVal, err := srv.getTaskBodyV2(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   90,
		Fn:         srv.retryGetTaskBody,
	})
	if err != nil {
		return utils.GenerateError("TaskBodyError", err.Error())
	}

	//! 上线前二次检查
	err = srv.doubleCheck(ctx)
	if err != nil {
		return err
	}

	//! 上线前检查是否有修改痕迹(判断状态)
	expectStatus := []string{
		common.DoubleCheckSuccessStatus,
	}
	err = tk.UpdateTicketStats(
		dto.TicketDTO{
			BusinessRef: srv.BusinessRef,
		},
		common.OnlinePassedStatus, expectStatus...)
	if err != nil {
		return err
	}

	//! 发起执行SQL_QUERY的事件
	ep.Produce(event.Event{
		Type: "sql_query",
		Payload: &core.QTaskGroupV2{
			TicketID:       srv.UID,
			GID:            utils.GenerateUUIDKey(), //! 全局任务ID
			UserID:         srv.UserID,
			DBName:         taskBodyVal.DBName,
			Env:            taskBodyVal.Env,
			Service:        taskBodyVal.Service,
			StmtRaw:        taskBodyVal.Statement,
			IsExport:       taskBodyVal.IsExport,
			IsLongTime:     taskBodyVal.LongTime,
			IsSoarAnalysis: taskBodyVal.IsSOAR,
			IsAiAnalysis:   taskBodyVal.IsAiAnalysis,
		},
		MetaData: event.EventMeta{
			Source:    "api",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
			TraceID:   srv.BusinessRef,
		},
	})
	return nil
}

// 从数据库中获取任务Body(抽象版)
func (srv *APITaskService) getTaskBodyV2(ctx context.Context, redo ReExcute) (dto.SQLTaskRequest, error) {
	// 获取Task Body数据
	var taskBodyVal dto.SQLTaskRequest
	body, exist := core.APITaskBodyMap.Get(srv.UID)
	if !exist {
		if redo.IsReExcute {
			// TODO: 补充超时控制context
			go redo.Fn()
			ticker := time.NewTicker(time.Duration(time.Second))
			defer ticker.Stop()
			// 超时控制
			timeout, cancel := context.WithTimeout(ctx, time.Duration(redo.Deadline)*time.Second)
			defer cancel()

		redoLoop:
			for {
				select {
				case <-ticker.C:
					mapVal, ok := core.APITaskBodyMap.Get(srv.UID)
					if !ok {
						continue
					}
					tempTaskBody, ok := mapVal.(dto.SQLTaskRequest)
					if !ok {
						return dto.SQLTaskRequest{}, utils.GenerateError("TaskBodyError", "API Task Body Type is not match")
					}
					taskBodyVal = tempTaskBody

					break redoLoop
				case <-timeout.Done():
					return dto.SQLTaskRequest{}, utils.GenerateError("ReExcuteTask", "re-excute task is timeout...")
				}
			}
		}
		return taskBodyVal, nil
	} else {
		tempTaskBody, ok := body.(dto.SQLTaskRequest)
		if !ok {
			return dto.SQLTaskRequest{}, utils.GenerateError("TaskBodyError", "API Task Body Type is not match")
		}
		taskBodyVal = tempTaskBody
	}
	return taskBodyVal, nil
}

// 从数据库重新获取数据，存储回内存。
func (srv *APITaskService) retryGetTaskBody() {
	tk := NewTicketService()
	dataORM := tk.toORMData(dto.TicketDTO{
		UID: srv.UID,
	})
	res, err := tk.DAO.FindOne(dataORM)
	if err != nil {
		utils.ErrorPrint("RedoError", err.Error())
	}
	taskBodyData := dto.SQLTaskRequest{
		ID:           res.TaskContent.ID,
		Env:          res.TaskContent.Env,
		Service:      res.TaskContent.Service,
		DBName:       res.TaskContent.DBName,
		Statement:    res.TaskContent.Statement,
		LongTime:     res.TaskContent.LongTime,
		IsExport:     res.TaskContent.IsExport,
		IsSOAR:       res.TaskContent.IsSOAR,
		IsAiAnalysis: res.TaskContent.IsAiAnalysis,
	}
	// !存储在Sync.Map中
	core.APITaskBodyMap.Set(srv.UID, taskBodyData, common.DefaultCacheMapDDL, common.APITaskBodyMapCleanFlag)
}

func (srv *APITaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
	// 获取Task Body数据v2 重做机制版
	taskBodyVal, err := srv.getTaskBodyV2(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   90,
		Fn:         srv.retryGetTaskBody,
	})
	if err != nil {
		return utils.GenerateError("TaskBodyError", err.Error())
	}

	// 更新Ticket信息(正在处理预检)
	targetStats := []string{
		common.CreatedStatus,
		common.EditedStatus,
		common.ReInitedStatus,
		common.DoubleCheckingStatus,
	}
	tk := NewTicketService()
	err = tk.UpdateTicketStats(dto.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckingStatus, targetStats...)
	if err != nil {
		return err
	}

	// 解析SQL
	parseStmts, err := core.ParseV3(ctx, taskBodyVal.Statement)
	if err != nil {
		return err
	}
	resultGroup.Data.ParsedSQL = parseStmts

	// EXPLAIN 解析与建议
	var analysisOpts core.AnalysisFnOpts = core.AnalysisFnOpts{
		WithExplain: true,
	}
	// 启用AI分析
	if taskBodyVal.IsAiAnalysis {
		analysisOpts.WithExplain = true
		analysisOpts.WithAi = true
		analysisOpts.WithDDL = true
		analysisOpts.WithSchema = true
	}
	for _, stmt := range parseStmts {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			taskBodyVal.Env,
			taskBodyVal.DBName,
			taskBodyVal.Service,
			analysisOpts,
		)
		if err != nil {
			return err
		}
		resultGroup.Data.ExplainAnalysis = append(resultGroup.Data.ExplainAnalysis, *analysisRes)

	}

	// SOAR 分析（利用系统层面SOAR操作实现，捕获屏幕输出流）
	if taskBodyVal.IsSOAR {
		soar := core.NewSoarAnalyzer(
			core.WithReportFormat("json"),
			core.WithSQLContent(taskBodyVal.Statement),
			core.WithCommandPath("/opt"),
			core.WithCommand("soar.linux-amd64_v11"),
		)
		soarResult, err := soar.Analysis()
		if err != nil {
			return err
		}
		resultGroup.Data.Soar.Results = soarResult
	}

	// !自定义规则解析
	ist, err := dbo.HaveDBIst(taskBodyVal.Env, taskBodyVal.DBName, taskBodyVal.Service)
	if err != nil {
		return err
	}
	// 1. 检查黑名单（数据库和数据表）
	dbPool := dbo.GetDBPoolManager()
	illegalDBs := dbPool.ExcludeDBList()
	illegalTables := ist.ExcludeTableList()
	recuErrCh := make(chan error, 1)
	// 递归版
	var recu func([]core.FromParse)
	for _, stmt := range parseStmts {
		stmtVal := stmt //! 避免闭包循环引用问题
		recu = func(froms []core.FromParse) {
			// goroutine 资源控制
			select {
			case <-ctx.Done():
				recuErrCh <- utils.GenerateError("GoroutineError", "Goroutine Break Off")
				return
			default:
				for _, f := range froms {
					// 需要处理派生表的情况（subFrom出现违规表)
					if slices.Contains(illegalDBs, f.DBName) {
						recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL DB Name is illegal.Statement: `%s`", f.DBName, stmt.SafeStmt))
						return
					}
					if slices.Contains(illegalTables, f.TableName) {
						recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL Table Name is illegal.Statement: `%s`", f.TableName, stmt.SafeStmt))
						return
					}
					if f.IsDerivedTable {
						recu(f.SubFrom)
					}

				}
			}
			// 2. 检查是否可写
			if !ist.IsWrite && stmtVal.Action != "select" {
				recuErrCh <- utils.GenerateError("NoPermission", "Your DB Instance is no permission")
				return
			}

		}
		recu(stmtVal.From)
	}
	recuErrCh <- nil // 预检成功
	if err := <-recuErrCh; err != nil {
		return err
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dto.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckSuccessStatus, common.PreCheckingStatus)
	if err != nil {
		return err
	}

	return nil
}

// 上线前双重检查(支持重做)，返回任务内容
func (srv *APITaskService) doubleCheck(ctx context.Context) error {
	doubleCheckVal := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}

	// 更新Ticket信息(正在处理预检)
	tk := NewTicketService()
	err := tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, common.DoubleCheckingStatus, common.ApprovalPassedStatus)
	if err != nil {
		return err
	}
	//! 获取首次预检结果 (如果不存在，则不重新解析)
	preCheckVal, err := srv.getPreCheckResult(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   300,
		Fn:         srv.ReCheck,
	})
	if err != nil {
		return utils.GenerateError("PreCheckResultError", err.Error())
	}
	preCheckVal.IsDoubleCheck = true

	if !preCheckVal.IsReDone {
		// 获取Task Body数据v2 重做机制版
		taskBodyVal, err := srv.getTaskBodyV2(ctx, ReExcute{
			IsReExcute: true,
			Deadline:   90,
			Fn:         srv.retryGetTaskBody,
		})
		if err != nil {
			return utils.GenerateError("TaskBodyError", err.Error())
		}

		// 仅EXPLAIN解析（用于对比检查）
		for _, stmt := range preCheckVal.Data.ParsedSQL {
			analysisRes, err := stmt.ExplainAnalysis(ctx,
				taskBodyVal.Env,
				taskBodyVal.DBName,
				taskBodyVal.Service,
				core.AnalysisFnOpts{
					WithExplain: true,
				},
			)
			if err != nil {
				return err
			}
			doubleCheckVal.Data.ExplainAnalysis = append(doubleCheckVal.Data.ExplainAnalysis, *analysisRes)
		}

		// TODO：是否要加入SELECT COUNT(*)的数据量对比

		//TODO: 对比首次预检检查结果
		for i, analysis := range doubleCheckVal.Data.ExplainAnalysis {
			for j, val := range analysis.Explain.Results {
				fritst := preCheckVal.Data.ExplainAnalysis[i].Explain.Results[j]
				if val["type"] == fritst["type"] {
					fmt.Println("debug print::double check ", val["type"])
				}
				// TODO: 对比数据量是否激增
			}
		}
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, common.DoubleCheckSuccessStatus, common.DoubleCheckingStatus)
	if err != nil {
		return err
	}
	return nil
}

func (srv *APITaskService) ReCheck() {
	// TODO:检查的重做函数
	ep := event.GetEventProducer()

	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID: srv.UID,
			UserID:   srv.UserID,
			Source:   common.APISourceFlag,
			Ref:      srv.BusinessRef,
		},
		MetaData: event.EventMeta{
			Source:    "api",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
			TraceID:   srv.BusinessRef,
		},
	})
}

// ! 执行任务
func (srv *APITaskService) Excute(ctx context.Context, qtg *core.QTaskGroupV2) error {
	errCh := make(chan error, 1)
	ep := event.GetEventProducer()
	go func() {
		// （更新）Ticket记录
		tk := NewTicketService()
		err := tk.UpdateTicketStats(dto.TicketDTO{
			BusinessRef: srv.BusinessRef,
		}, common.PendingStatus, common.OnlinePassedStatus)
		if err != nil {
			errCh <- err
			return
		}

		// 获取雪花ID进行链路追踪
		tkID := srv.getTicketID()
		srv.UID = tkID
		// ! 获取预检结果 (如果不存在，则不重做，直接返回报错。)
		preCheckVal, err := srv.getPreCheckResult(ctx, ReExcute{
			IsReExcute: false,
		})
		if err != nil {
			errCh <- err
			return
		}

		//! 构造任务组V3
		core.QueryTaskMap.Set(srv.UID, qtg, common.DefaultCacheMapDDL, common.QueryTaskMapCleanFlag)

		taskGroup := make([]*core.SQLTask, 0)
		var maxDeadline int
		// 分别定义每个SQL语句的超时时间，SELECT和其他DML的不同超时时间
		for _, s := range preCheckVal.Data.ParsedSQL {
			var ddl int
			if qtg.IsLongTime {
				if s.Action == "select" {
					ddl = common.LongSelectDDL
				} else {
					ddl = common.LongOtherDDL
				}
			} else {
				if s.Action == "select" {
					ddl = common.SelectDDL
				} else {
					ddl = common.OtherDDL
				}
			}
			qTask := core.SQLTask{
				ID:        utils.GenerateUUIDKey(),
				ParsedSQL: s,
				Deadline:  ddl,
			}
			taskGroup = append(taskGroup, &qTask)
			maxDeadline += ddl
		}
		qtg.QTasks = taskGroup
		qtg.Deadline = maxDeadline + 60
		qtg.TicketID = srv.UID
		// 执行查询任务组v2
		resultGroup := qtg.ExcuteTask(ctx)
		resultGroup.TicketID = srv.UID
		ep.Produce(event.Event{
			Type:    "save_result",
			Payload: resultGroup,
			MetaData: event.EventMeta{
				Source:    "api",
				Operator:  int(srv.UserID),
				Timestamp: time.Now().Format("20060102150405"),
				TraceID:   srv.BusinessRef,
			},
		})
		// 日志审计插入v2
		jsonBytes, err := json.Marshal(taskGroup)
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		auditLogSrv := NewAuditRecordService()
		err = auditLogSrv.Insert(dto.AuditRecordDTO{
			TaskID:    qtg.GID,
			UserID:    qtg.UserID,
			Payload:   string(jsonBytes),
			TaskType:  common.APITaskType,
			EventType: "SQL_QUERY",
			TicketID:  tkID,
		})
		if err != nil {
			errCh <- err
			return
		}
	}()

	// 统一错误处理
	select {
	case err := <-errCh:
		if err != nil {
			err := srv.UpdateTicketStats(common.FailedStatus)
			if err != nil {
				utils.ErrorPrint("TicketStatsError", "Ticket Status update is failed")
			}

			// 传递携带错误信息的结果集
			ep.Produce(event.Event{
				Type: "save_result",
				Payload: &core.SQLResultGroupV2{
					Data:     nil,
					Errrr:    err,
					GID:      qtg.GID,
					TicketID: srv.UID,
				},
				MetaData: event.EventMeta{
					Source:    "api",
					Operator:  int(srv.UserID),
					Timestamp: time.Now().Format("20060102150405"),
					TraceID:   srv.BusinessRef,
				},
			})
		}
	case <-ctx.Done():
		utils.ErrorPrint("GoroutineErr", "goroutine is error")
	}
	return nil
}

// 存储结果集
func (srv *APITaskService) SaveResult(ctx context.Context, sqlResult *core.SQLResultGroupV2) error {
	tk := NewTicketService()
	//! 后期核心处理结果集的代码逻辑块
	core.ResultMap.Set(srv.UID, sqlResult, common.DefaultCacheMapDDL, common.ResultMapCleanFlag)

	// Ticket状态：成功
	err := tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, common.CompletedStatus, common.PendingStatus)
	if err != nil {
		return utils.GenerateError("TicketErr", err.Error())
	}
	taskContent, err := srv.getTaskBodyV2(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   90,
		Fn:         srv.retryGetTaskBody,
	})
	if err != nil {
		return err
	}

	// 存储临时结果集
	uuKey := utils.GenerateUUIDKey()
	tempResSrv := NewTempResultService(srv.UserID)
	err = tempResSrv.Insert(dto.TempResultDTO{
		UUKey:         uuKey,
		TaskID:        sqlResult.GID,
		TicketID:      srv.UID,
		IsAllowExport: taskContent.IsExport,
	}, common.DefaultCacheMapDDL)
	if err != nil {
		return err
	}

	return nil
}

// 直接更新Ticket状态
func (srv *APITaskService) UpdateTicketStats(targetStats string, exceptStats ...string) error {
	tk := NewTicketService()
	return tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, targetStats, exceptStats...)
}

// ! 通过TicketID获取预检结果集(支持重新解析)
func (srv *APITaskService) getPreCheckResult(ctx context.Context, redo ReExcute) (*core.PreCheckResultGroup, error) {
	var fristCheckVal *core.PreCheckResultGroup
	val, exist := core.CheckTaskMap.Get(srv.UID)
	if !exist {
		if redo.IsReExcute {
			fmt.Println("debug print 开启重做...")
			go redo.Fn()
			// 同步方式每秒检测是否查询任务完成，来获取结果集
			ticker := time.NewTicker(time.Duration(time.Second))
			defer ticker.Stop()
			// 超时控制
			timeout, cancel := context.WithTimeout(ctx, time.Duration(redo.Deadline))
			defer cancel()

			for {
				select {
				case <-ticker.C:
					mapVal, ok := core.CheckTaskMap.Get(srv.UID)
					if !ok {
						continue
					}
					fristCheckVal, ok = mapVal.(*core.PreCheckResultGroup)
					if !ok {
						return nil, utils.GenerateError("PreCheckResultError", "pre-check result type is incorrect")
					}
					fristCheckVal.IsReDone = true
					return fristCheckVal, nil
				case <-timeout.Done(): // TIMEOUT
					return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeout.")
				}
			}
		} else {
			return nil, utils.GenerateError("CheckResultError", "不存在该CheckTask数据，也没有开启重做机制")
		}

	}
	fristCheckVal, ok := val.(*core.PreCheckResultGroup)
	if !ok {
		return nil, utils.GenerateError("CheckResultError", "Frist Check Resul type is invalid")
	}
	return fristCheckVal, nil
}
