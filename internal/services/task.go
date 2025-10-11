package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	api "sql_demo/internal/api/dto"
	dto "sql_demo/internal/api/dto"
	clients "sql_demo/internal/clients/gitlab"
	glbapi "sql_demo/internal/clients/gitlab"
	wx "sql_demo/internal/clients/weixin"
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
type GitLabOption func(*GitLabTaskService)

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

func (srv *APITaskService) getTicketID() int64 {
	tk := NewTicketService()
	tkData := dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}
	return tk.GetUID(tkData)
}

func (srv *APITaskService) SaveCheckData(ctx context.Context, preCheckVal *core.PreCheckResultGroup) error {
	//! 存储预检任务信息
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
	tk := NewTicketService()
	// 利用business_ref间接获取雪花ID来获取其他数据
	tkID := srv.getTicketID()
	srv.UID = tkID

	val, exist := core.APITaskBodyMap.Get(tkID)
	if !exist {
		// TODO：如果不存在，则重新请求获取数据库中重新解析
		return utils.GenerateError("CacheNotExist", "api task cache is not exist")
	}
	taskBody, ok := val.(dto.SQLTaskRequest)
	if !ok {
		return utils.GenerateError("CacheNotMatch", "api task cache kind is not match")
	}
	ep := event.GetEventProducer()

	//! 上线前二次检查
	_, err := srv.DoubleCheck(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   common.RetryTimeOut,
		Fn:         srv.ReCheck,
	})
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
	//! 发起sql_query的事件，准备执行SQL
	ep.Produce(event.Event{
		Type: "sql_query",
		Payload: &core.QTaskGroupV2{
			TicketID:       srv.UID,
			GID:            utils.GenerateUUIDKey(), //! 全局任务ID
			UserID:         srv.UserID,
			DBName:         taskBody.DBName,
			Env:            taskBody.Env,
			Service:        taskBody.Service,
			StmtRaw:        taskBody.Statement,
			IsExport:       taskBody.IsExport,
			IsLongTime:     taskBody.LongTime,
			IsSoarAnalysis: taskBody.IsSOAR,
			IsAiAnalysis:   taskBody.IsAiAnalysis,
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

func (srv *APITaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
	// 获取Task Body数据
	body, exist := core.APITaskBodyMap.Get(srv.UID)
	if !exist {
		return utils.GenerateError("TaskBodyError", "API Task Body is not exist")
	}
	taskBodyVal, ok := body.(dto.SQLTaskRequest)
	if !ok {
		return utils.GenerateError("TaskBodyError", "API Task Body Type is not match")
	}

	// 更新Ticket信息(正在处理预检)
	targetStats := []string{
		common.CreatedStatus,
		common.EditedStatus,
		common.ReInitedStatus,
		common.DoubleCheckingStatus,
	}
	tk := NewTicketService()
	err := tk.UpdateTicketStats(dto.TicketDTO{
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

					// 2. 检查是否可写
					if !ist.IsWrite && stmtVal.Action != "select" {
						recuErrCh <- utils.GenerateError("NoPermission", "Your DB Instance is no permission")
						return
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

// 上线前双重检查
func (srv *APITaskService) DoubleCheck(ctx context.Context, redo ReExcute) (*core.PreCheckResultGroup, error) {
	var fristCheckVal *core.PreCheckResultGroup
	doubleCheckVal := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}

	// 获取APITask信息
	val, exist := core.APITaskBodyMap.Get(srv.UID)
	if !exist {
		return nil, utils.GenerateError("TaskBodyError", "API Task Body is not exist")
	}
	taskBodyVal, ok := val.(dto.SQLTaskRequest)
	if !ok {
		return nil, utils.GenerateError("TaskBodyError", "API Task Body type is assert failed")
	}

	// 更新Ticket信息(正在处理预检)
	tk := NewTicketService()
	err := tk.UpdateTicketStats(api.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, common.DoubleCheckingStatus, common.ApprovalPassedStatus)
	if err != nil {
		return nil, err
	}

	// ! 获取首次预检结果(重试版)
	val, exist = core.CheckTaskMap.Get(srv.UID)
	if !exist {
		if redo.IsReExcute {
			fmt.Println("涉及重做机制：DoubleCheck")
			// TODO：再次重新解析SQL
			redo.Fn()
			// 同步方式每秒检测是否查询任务完成，来获取结果集
			ticker := time.NewTicker(time.Duration(time.Second))
			defer ticker.Stop()
			// 超时控制
			timeout, cancel := context.WithTimeout(ctx, time.Duration(redo.Deadline)*time.Second)
			defer cancel()

		redoLoop:
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
					// 重新预检，再次进入double check
					err := tk.UpdateTicketStats(api.TicketDTO{
						BusinessRef: srv.BusinessRef,
					}, common.DoubleCheckingStatus, common.PreCheckSuccessStatus)
					if err != nil {
						return nil, err
					}
					break redoLoop
				case <-timeout.Done(): // TIMEOUT
					return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeout...")
				}
			}
		} else {
			return nil, utils.GenerateError("CheckResultError", "不存在该CheckTask数据，也没有开启重做机制")
		}

	} else {
		fristCheckVal, ok = val.(*core.PreCheckResultGroup)
		if !ok {
			return nil, utils.GenerateError("CheckResultError", "Frist Check Result is not exist")
		}
	}

	// 仅EXPLAIN解析（用于对比检查）
	for _, stmt := range fristCheckVal.Data.ParsedSQL {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			taskBodyVal.Env,
			taskBodyVal.DBName,
			taskBodyVal.Service,
			core.AnalysisFnOpts{
				WithExplain: true,
			},
		)
		if err != nil {
			return nil, err
		}
		doubleCheckVal.Data.ExplainAnalysis = append(doubleCheckVal.Data.ExplainAnalysis, *analysisRes)
	}

	// TODO：是否要加入SELECT COUNT(*)的数据量对比

	//TODO: 对比首次预检检查结果
	for i, analysis := range doubleCheckVal.Data.ExplainAnalysis {
		for j, val := range analysis.Explain.Results {
			fritst := fristCheckVal.Data.ExplainAnalysis[i].Explain.Results[j]
			//! (仅Explain type示例)
			if val["type"] == fritst["type"] {
				fmt.Println("debug print::double check ", val["type"])
			}
			// TODO: 对比数据量是否激增
		}
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, common.DoubleCheckSuccessStatus, common.DoubleCheckingStatus)
	if err != nil {
		return nil, err
	}

	return doubleCheckVal, nil
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
		// ! 获取首次预检结果 (如果不存在，则不重新解析)
		preCheckVal, err := getPreCheckResult(ctx, srv.UID, ReExcute{
			IsReExcute: false,
			Deadline:   common.RetryTimeOut,
			Fn:         srv.ReCheck,
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

	// // 存储结果、输出结果临时链接
	// uuKey, tempURL := glbapi.NewHashTempLink()
	// tempResSrv := NewTempResultService(srv.UserID)
	// err = tempResSrv.Insert(dto.TempResultDTO{
	// 	UUKey:         uuKey,
	// 	TaskID:        sqlResult.GID,
	// 	TicketID:      srv.UID,
	// 	IsAllowExport: IssueVal.QTG.IsExport,
	// }, common.DefaultCacheMapDDL)
	// if err != nil {
	// 	return err
	// }

	return nil
}

// 直接更新Ticket状态
func (srv *APITaskService) UpdateTicketStats(targetStats string, exceptStats ...string) error {
	tk := NewTicketService()
	return tk.UpdateTicketStats(dto.TicketDTO{
		BusinessRef: srv.BusinessRef,
	}, targetStats, exceptStats...)
}

// GitLab 调用
type GitLabTaskService struct {
	SourceRef string
	UID       int64
	IssueIID  uint
	ProjectID uint
	UserID    uint
}

func NewGitLabTaskService(opts ...GitLabOption) *GitLabTaskService {
	gitlabTask := &GitLabTaskService{}
	for _, opt := range opts {
		opt(gitlabTask)
	}
	return gitlabTask
}

func WithGitLabTaskUID(uid int64) GitLabOption {
	return func(as *GitLabTaskService) {
		as.UID = uid
	}
}

func WithGitLabTaskUserID(userID uint) GitLabOption {
	return func(as *GitLabTaskService) {
		as.UserID = userID
	}
}

func WithGitLabTaskProjectID(projectID uint) GitLabOption {
	return func(as *GitLabTaskService) {
		as.ProjectID = projectID
	}
}

func WithGitLabTaskIssueIID(issueIID uint) GitLabOption {
	return func(as *GitLabTaskService) {
		as.IssueIID = issueIID
	}
}

// GitLab调用创建SQLTask和Ticket
func (srv *GitLabTaskService) Create(payload *IssuePayload) (*dto.TicketDTO, error) {
	// 获取用户真实ID
	user := dbo.User{
		GitLabIdentity: payload.Issue.AuthorID,
	}
	userID := user.GetGitLabUserId()
	// 创建Ticket(需要根据客户端来主动构造business_ref)信息
	tk := NewTicketService()
	busniessDomain := "sql-task"
	// {业务域}:{来源}:{项目ID}:{议题IID}:user:{主体id}
	sourceRef := fmt.Sprintf("%s:%s:%d:%d:user:%d", busniessDomain, "gitlab", payload.Issue.ProjectID, payload.Issue.IID, userID)
	// 幂等性键等同于sourceRef
	IdempKey := sourceRef

	tkData := dto.TicketDTO{
		Status:         common.CreatedStatus,
		SourceRef:      sourceRef,
		IdemoptencyKey: IdempKey,
		AuthorID:       userID,
		ProjectID:      payload.Issue.ProjectID,
		IssueIID:       payload.Issue.IID,
		Source:         common.GitLabSourceFlag,
	}
	tkID, err := tk.CreateOrUpdate(tkData)
	if err != nil {
		return nil, err
	}
	tkData.UID = tkID

	// 缓存issue信息，若找不到则从数据库中查找。
	issCache := &IssueCache{
		Content: payload.Desc,
		Issue:   payload.Issue,
	}
	core.GitLabIssueMap.Set(tkData.UID, issCache, common.TicketCacheMapDDL, common.GitLabTaskType)

	//  创建SQLTask的审计日志
	taskBody, err := json.Marshal(issCache)
	if err != nil {
		return nil, err
	}
	auditLogSrv := NewAuditRecordService()
	err = auditLogSrv.Insert(dto.AuditRecordDTO{
		UserID:    userID,
		Payload:   string(taskBody),
		TaskType:  common.GitLabTaskType,
		ProjectID: issCache.ProjectID,
		IssueID:   issCache.IID,
		EventType: "TASK_CREATED",
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
			Source:   common.GitLabSourceFlag,
			Ref:      tkData.SourceRef,
		},
		MetaData: event.EventMeta{
			Source:    "gitlab",
			Operator:  int(userID),
			Timestamp: time.Now().Format("20060102150405"),
			// ! 临时额外增加
			ProjectID: payload.Issue.ProjectID,
			IssueIID:  payload.Issue.IID,
		},
	})

	return &tkData, nil
}

// TODO: 重新分析
// func (srv *GitLabTaskService) ReAnalysis(payload *IssuePayload, redo ReExcute) error {
// 	// 获取用户真实ID
// 	user := dbo.User{
// 		GitLabIdentity: payload.Issue.AuthorID,
// 	}
// 	userID := user.GetGitLabUserId()
// 	// 创建Ticket(需要根据客户端来主动构造business_ref)信息
// 	tk := NewTicketService()
// 	busniessDomain := "sql-task"
// 	// {业务域}:{来源}:{项目ID}:{议题IID}:user:{主体id}
// 	sourceRef := fmt.Sprintf("%s:%s:%d:%d:user:%d", busniessDomain, "gitlab", payload.Issue.ProjectID, payload.Issue.IID, userID)
// 	// 幂等性键等同于sourceRef
// 	IdempKey := sourceRef

// 	tkData := dto.TicketDTO{
// 		Status:         common.CreatedStatus,
// 		SourceRef:      sourceRef,
// 		IdemoptencyKey: IdempKey,
// 		AuthorID:       userID,
// 		ProjectID:      payload.Issue.ProjectID,
// 		IssueIID:       payload.Issue.IID,
// 		Source:         common.GitLabSourceFlag,
// 	}
// 	tkID, err := tk.CreateOrUpdate(tkData)
// 	if err != nil {
// 		return err
// 	}
// 	tkData.UID = tkID
// 	fmt.Println("debug print -1:", tkID)

// 	// 缓存issue信息，若找不到则从数据库中查找。
// 	issCache := &IssueCache{
// 		Content: payload.Desc,
// 		Issue:   payload.Issue,
// 	}
// 	core.GitLabIssueMap.Set(tkData.UID, issCache, common.TicketCacheMapDDL, common.IssueTicketType)
// 	return nil
// }

func (srv *GitLabTaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
	// 获取Task Body数据(GItlab)
	val, exist := core.GitLabIssueMap.Get(srv.UID)
	if !exist {
		return utils.GenerateError("GitLabIssueNotExist", "Issue Cache is not exist")

	}
	issCache, ok := val.(*IssueCache)
	if !ok {
		return utils.GenerateError("GitLabIssueInvalid", "Issue Cache type is invalid")

	}
	srv.ProjectID = issCache.ProjectID
	srv.IssueIID = issCache.IID

	// 更新Ticket信息(正在处理预检)
	targetStats := []string{
		common.CreatedStatus,
		common.EditedStatus,
		common.ReInitedStatus,
		common.DoubleCheckingStatus,
	}
	tk := NewTicketService()
	err := tk.UpdateTicketStats(dto.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckingStatus, targetStats...)
	if err != nil {
		srv.NotifyGitLab(err.Error())
		return err

	}

	//TODO: 增强SQL解析
	parseStmts, err := core.ParseV3(ctx, issCache.Content.Statement)
	if err != nil {
		srv.NotifyGitLab(err.Error())
		return err
	}
	resultGroup.Data.ParsedSQL = parseStmts

	// EXPLAIN 解析与建议
	var analysisOpts core.AnalysisFnOpts = core.AnalysisFnOpts{
		WithExplain: true,
	}
	// 启用AI分析
	if issCache.Content.IsAiAnalysis {
		analysisOpts.WithAi = true
		analysisOpts.WithDDL = true
		analysisOpts.WithSchema = true
	}
	for _, stmt := range parseStmts {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			issCache.Content.Env,
			issCache.Content.DBName,
			issCache.Content.Service,
			analysisOpts,
		)
		if err != nil {
			srv.NotifyGitLab(err.Error())
			return err
		}
		resultGroup.Data.ExplainAnalysis = append(resultGroup.Data.ExplainAnalysis, *analysisRes)
		// 输出到gitlab中
		if issCache.Content.IsAiAnalysis {
			srv.NotifyGitLab(analysisRes.AiAnalysis)
		}
	}

	// SOAR 分析（利用系统层面SOAR操作实现，捕获屏幕输出流）
	if issCache.Content.IsSoarAnalysis {
		soar := core.NewSoarAnalyzer(
			core.WithReportFormat("json"),
			core.WithSQLContent(issCache.Content.Statement),
			core.WithCommandPath("/opt"),
			core.WithCommand("soar.linux-amd64_v11"),
		)
		soarResult, err := soar.Analysis()
		if err != nil {
			srv.NotifyGitLab(err.Error())
			return err
		}
		resultGroup.Data.Soar.Results = soarResult
	}

	// !自定义规则解析
	ist, err := dbo.HaveDBIst(issCache.Content.Env, issCache.Content.DBName, issCache.Content.Service)
	if err != nil {
		srv.NotifyGitLab(err.Error())
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
		srv.NotifyGitLab(err.Error())
		return err
	}
	// 更新Ticket信息
	err = tk.UpdateTicketStats(dto.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckSuccessStatus, common.PreCheckingStatus)
	if err != nil {
		srv.NotifyGitLab(err.Error())
		return err
	}
	return nil
}

func (srv *GitLabTaskService) DoubleCheck(ctx context.Context, redo ReExcute) (*core.PreCheckResultGroup, error) {
	var fristCheckVal *core.PreCheckResultGroup
	doubleCheckVal := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}

	// 获取Issue信息
	val, exist := core.GitLabIssueMap.Get(srv.UID)
	if !exist {
		return nil, utils.GenerateError("GitLabIssueNotExist", "Issue Cache is not exist")
	}
	issCache, ok := val.(*IssueCache)
	if !ok {
		return nil, utils.GenerateError("GitLabIssueInvalid", "Issue Cache type is invalid")
	}
	srv.ProjectID = issCache.ProjectID
	srv.IssueIID = issCache.IID

	// 更新Ticket信息(正在处理预检)
	tk := NewTicketService()
	err := tk.UpdateTicketStats(api.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.DoubleCheckingStatus, common.ApprovalPassedStatus)
	if err != nil {
		srv.NotifyGitLab(err.Error())
		return nil, err
	}

	// ! 获取首次预检结果(重试版)
	val, exist = core.CheckTaskMap.Get(srv.UID)
	if !exist {
		if redo.IsReExcute {
			fmt.Println("涉及重做机制：DoubleCheck")
			// TODO：再次重新解析SQL
			redo.Fn()
			// 同步方式每秒检测是否查询任务完成，来获取结果集
			ticker := time.NewTicker(time.Duration(time.Second))
			defer ticker.Stop()
			// 超时控制
			timeout, cancel := context.WithTimeout(ctx, time.Duration(redo.Deadline)*time.Second)
			defer cancel()

		redoLoop:
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
					// 重新预检，再次进入double check
					err := tk.UpdateTicketStats(api.TicketDTO{
						UID:      srv.UID,
						AuthorID: srv.UserID,
					}, common.DoubleCheckingStatus, common.PreCheckSuccessStatus)
					if err != nil {
						srv.NotifyGitLab(err.Error())
						return nil, err
					}
					break redoLoop
				case <-timeout.Done(): // TIMEOUT
					return nil, utils.GenerateError("ReExcuteTask", "re-excute task is timeout...")
				}
			}
		} else {
			return nil, utils.GenerateError("CheckResultError", "不存在该CheckTask数据，也没有开启重做机制")
		}

	} else {
		fristCheckVal, ok = val.(*core.PreCheckResultGroup)
		if !ok {
			srv.NotifyGitLab("Frist Check Result is not exist")
			return nil, utils.GenerateError("CheckResultError", "Frist Check Result is not exist")
		}
	}

	// 仅EXPLAIN解析（用于对比检查）
	for _, stmt := range fristCheckVal.Data.ParsedSQL {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			issCache.Content.Env,
			issCache.Content.DBName,
			issCache.Content.Service,
			core.AnalysisFnOpts{
				WithExplain: true,
			},
		)
		if err != nil {
			srv.NotifyGitLab(err.Error())
			return nil, err
		}
		doubleCheckVal.Data.ExplainAnalysis = append(doubleCheckVal.Data.ExplainAnalysis, *analysisRes)
	}

	// TODO：是否要加入SELECT COUNT(*)的数据量对比

	//! 对比首次预检检查结果
	for i, analysis := range doubleCheckVal.Data.ExplainAnalysis {
		for j, val := range analysis.Explain.Results {
			fritst := fristCheckVal.Data.ExplainAnalysis[i].Explain.Results[j]
			//! (仅Explain type示例)
			if val["type"] == fritst["type"] {
				fmt.Println("debug print::double check ", val["type"])
			}
		}
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dto.TicketDTO{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.DoubleCheckSuccessStatus, common.DoubleCheckingStatus)
	if err != nil {
		srv.NotifyGitLab(err.Error())
		return nil, err
	}

	return doubleCheckVal, nil
}

// 检查任务重做
func (srv *GitLabTaskService) ReCheck() {
	ep := event.GetEventProducer()
	updateMsg := fmt.Sprintf("TicketID=%d Pre-Check Task is Re-Excute...", srv.UID)
	srv.NotifyGitLab(updateMsg)

	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID: srv.UID,
			UserID:   srv.UserID,
		},
		MetaData: event.EventMeta{
			Source:    "gitlab",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
		},
	})
}

// 通过AuthorID+ProjectID+IssueIID获取Ticket UID
func (srv *GitLabTaskService) GetTicketUID() int64 {
	tkData, err := srv.getTicket()
	if err != nil {
		return 0
	}
	return tkData.UID
}

// 通过AuthorID+ProjectID+IssueIID获取Ticket
func (srv *GitLabTaskService) getTicket() (*dbo.Ticket, error) {
	tk := NewTicketService()
	condORM := tk.toORMData(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	})
	return tk.DAO.FindOne(condORM)
}

// 通过UID获取Ticket
func (srv *GitLabTaskService) getTicketByUID() (*dbo.Ticket, error) {
	tk := NewTicketService()
	condORM := tk.toORMData(dto.TicketDTO{
		UID: srv.UID,
	})
	return tk.DAO.FindOne(condORM)
}

func (srv *GitLabTaskService) approval(ctx context.Context) error {
	// 校验状态并更新Ticket
	expectStatus := []string{
		common.PreCheckSuccessStatus,
		common.CompletedStatus,
		common.ApprovalPassedStatus,
	}
	tk := NewTicketService()
	sourceRef := tk.GetSourceRef(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	})
	err := tk.UpdateTicketStats(dto.TicketDTO{
		SourceRef: sourceRef,
	}, common.ApprovalPassedStatus, expectStatus...)
	//! Gitlab评论方式通知更新情况
	// _ = glab.CommentCreate(glbapi.GitLabComment{
	// 	ProjectID: commentBody.ProjectID,
	// 	IssueIID:  commentBody.IssueIID,
	// 	Message:   "审批成功, 等待上线...",
	// })
	return err
}

func (srv *GitLabTaskService) reject(ctx context.Context) error {
	// 获取Task Body数据(GItlab)
	expectStatus := []string{
		common.PreCheckSuccessStatus,
		common.PreCheckFailedStatus,
	}
	// （更新）Ticket记录
	tk := NewTicketService()
	sourceRef := tk.GetSourceRef(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	})
	err := tk.UpdateTicketStats(dto.TicketDTO{
		SourceRef: sourceRef,
	}, common.ApprovalRejectStatus, expectStatus...)
	return err
}

func (srv *GitLabTaskService) online(ctx context.Context) error {
	// 利用UID获取gitlab issue缓存
	val, exist := core.GitLabIssueMap.Get(srv.UID)
	if !exist {
		// TODO：如果不存在，则重新请求GitLab API进行获取解析
		// srv.ReAnalysis()

		return utils.GenerateError("CacheNotExist", "gitlab issue cache is not exist")
	}
	issueCaches, ok := val.(*IssueCache)
	if !ok {
		return utils.GenerateError("CacheNotMatch", "gitlab issue cache kind ")
	}
	sqlt := issueCaches.Content
	issue := issueCaches.Issue
	ep := event.GetEventProducer()

	//!上线前二次检查
	_, err := srv.DoubleCheck(ctx, ReExcute{
		IsReExcute: true,
		Deadline:   common.RetryTimeOut,
		Fn:         srv.ReCheck,
	})
	if err != nil {
		return err
	}

	// （更新）Ticket记录,检查是否有修改痕迹
	tk := NewTicketService()
	sourceRef := tk.GetSourceRef(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	})
	err = tk.UpdateTicketStats(dto.TicketDTO{
		SourceRef: sourceRef,
	}, common.OnlinePassedStatus, common.DoubleCheckSuccessStatus)
	if err != nil {
		return err
	}

	//! 发起sql_query的事件，准备执行SQL
	ep.Produce(event.Event{
		Type: "sql_query",
		Payload: &core.IssueQTaskV2{
			QTG: &core.QTaskGroupV2{
				TicketID:       srv.UID,
				GID:            utils.GenerateUUIDKey(),
				DML:            issueCaches.Action,
				UserID:         srv.UserID,
				DBName:         sqlt.DBName,
				Env:            sqlt.Env,
				Service:        sqlt.Service,
				StmtRaw:        sqlt.Statement,
				IsExport:       sqlt.IsExport,
				IsLongTime:     sqlt.LongTime,
				IsSoarAnalysis: sqlt.IsSoarAnalysis,
				IsAiAnalysis:   sqlt.IsAiAnalysis,
			},
			IssProjectID:  issue.ProjectID,
			IssIID:        issue.IID,
			IssAuthorID:   issue.AuthorID,
			IssAuthorName: issue.Author.Name,
		},
		MetaData: event.EventMeta{
			Source:    "gitlab",
			Operator:  int(srv.UserID),
			Timestamp: time.Now().Format("20060102150405"),
		},
	})
	return nil
}

// 审批通过或者驳回请求
func (srv *GitLabTaskService) ActionHandle(ctx context.Context, status int) error {
	switch status {
	case common.ApprovalActionFlag:
		return srv.approval(ctx)
	case common.RejectActionFlag:
		return srv.reject(ctx)
	case common.OnlineActionFlag:
		return srv.online(ctx)
	default:
		return errors.New("unknown Action")
	}
}

// ! 执行任务
func (srv *GitLabTaskService) Excute(ctx context.Context, issQTG *core.IssueQTaskV2) error {
	errCh := make(chan error, 1)
	ep := event.GetEventProducer()
	glab := glbapi.InitGitLabAPI()
	go func() {
		// （更新）Ticket记录
		tk := NewTicketService()
		sourceRef := tk.GetSourceRef(dto.TicketDTO{
			AuthorID:  srv.UserID,
			ProjectID: uint(srv.ProjectID),
			IssueIID:  uint(srv.IssueIID),
		})
		err := tk.UpdateTicketStats(dto.TicketDTO{
			SourceRef: sourceRef,
		}, common.PendingStatus, common.OnlinePassedStatus)
		if err != nil {
			errCh <- err
			return
		}

		// ! 获取首次预检结果 (如果不存在，则不重新解析)
		preCheckVal, err := getPreCheckResult(ctx, srv.UID, ReExcute{
			IsReExcute: false,
			Deadline:   common.RetryTimeOut,
			Fn:         srv.ReCheck,
		})
		if err != nil {
			errCh <- err
			return
		}

		//！ 构造任务组V3
		core.QueryTaskMap.Set(srv.UID, issQTG, common.DefaultCacheMapDDL, common.QueryTaskMapCleanFlag)

		updateMsg := fmt.Sprintf("TaskGID=%s is start work...", issQTG.QTG.GID)
		err = glab.CommentCreate(glbapi.GitLabComment{
			ProjectID: issQTG.IssProjectID,
			IssueIID:  issQTG.IssIID,
			Message:   updateMsg,
		})
		if err != nil {
			errCh <- err
			return
		}

		taskGroup := make([]*core.SQLTask, 0)
		var maxDeadline int
		// 分别定义每个SQL语句的超时时间，SELECT和其他DML的不同超时时间
		for _, s := range preCheckVal.Data.ParsedSQL {
			var ddl int
			if issQTG.QTG.IsLongTime {
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
		issQTG.QTG.QTasks = taskGroup
		issQTG.QTG.Deadline = maxDeadline + 60
		issQTG.QTG.TicketID = srv.UID
		// 执行查询任务组v2
		resultGroup := issQTG.QTG.ExcuteTask(ctx)
		resultGroup.TicketID = srv.UID
		ep.Produce(event.Event{
			Type:    "save_result",
			Payload: resultGroup,
			MetaData: event.EventMeta{
				Source:    "gitlab",
				Operator:  int(srv.UserID),
				Timestamp: time.Now().Format("20060102150405"),
			},
		})
		// 日志审计插入v2
		jsonBytes, err := json.Marshal(taskGroup)
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		auditLogSrv := NewAuditRecordService()
		err = auditLogSrv.Insert(dto.AuditRecordDTO{
			TaskID:    issQTG.QTG.GID,
			UserID:    issQTG.QTG.UserID,
			Payload:   string(jsonBytes),
			ProjectID: issQTG.IssProjectID,
			IssueID:   issQTG.IssIID,
			TaskType:  common.GitLabTaskType,
			EventType: "SQL_QUERY",
		})
		if err != nil {
			errCh <- err
			return
		}
	}()

	// 统一错误处理(没错误的话已在Excute中完成了事件流转)
	select {
	case err := <-errCh:
		if err != nil {
			srv.UpdateTicketStatus(common.FailedStatus)
			_ = glab.CommentCreate(glbapi.GitLabComment{
				ProjectID: issQTG.IssProjectID,
				IssueIID:  issQTG.IssIID,
				Message:   err.Error(),
			})
			ep.Produce(event.Event{
				Type: "save_result",
				Payload: &core.SQLResultGroupV2{
					Data:     nil,
					Errrr:    err,
					GID:      issQTG.QTG.GID,
					TicketID: srv.UID,
				},
				MetaData: event.EventMeta{
					Source:    "gitlab",
					Operator:  int(srv.UserID),
					Timestamp: time.Now().Format("20060102150405"),
				},
			})
		}
	case <-ctx.Done():
		utils.ErrorPrint("GoroutineErr", "goroutine is error")
	}
	return nil
}

// 修改Ticket的状态
func (srv *GitLabTaskService) UpdateTicketStatus(status string) error {
	tk := NewTicketService()
	sourceRef := tk.GetSourceRef(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	})
	err := tk.UpdateTicketStats(dto.TicketDTO{
		SourceRef: sourceRef,
	}, status)
	return err
}

func (srv *GitLabTaskService) SaveResult(ctx context.Context, sqlResult *core.SQLResultGroupV2) error {
	glab := glbapi.InitGitLabAPI()
	// 获取Ticket信息
	tk, err := srv.getTicketByUID()
	if err != nil {
		return err
	}
	// 处理整体的业务错误
	if sqlResult.Errrr != nil {
		err := glab.CommentCreate(glbapi.GitLabComment{
			ProjectID: uint(tk.ProjectID),
			IssueIID:  uint(tk.IssueID),
			Message:   sqlResult.Errrr.Error(),
		})
		if err != nil {
			utils.ErrorPrint("GitlabCommentErr", err.Error())
		}
	}
	//! 后期核心处理结果集的代码逻辑块
	core.ResultMap.Set(srv.UID, sqlResult, common.DefaultCacheMapDDL, common.ResultMapCleanFlag)
	// （更新）Ticket记录, Issue评论情况更新

	updateMsg := fmt.Sprintf("TaskGID=%s is completed", sqlResult.GID)
	err = glab.CommentCreate(glbapi.GitLabComment{
		ProjectID: uint(tk.ProjectID),
		IssueIID:  uint(tk.IssueID),
		Message:   updateMsg,
	})
	if err != nil {
		utils.ErrorPrint("GitlabCommentErr", err.Error())
	}

	// 遍历每条SQL的细致Error
	for _, result := range sqlResult.Data {
		if result.Errrrr != nil {
			errMsg := fmt.Sprintf("TicketID=%s\n- IID=%s\n- TaskError=%s", sqlResult.GID, result.ID, result.ErrMsg)
			err := glab.CommentCreate(glbapi.GitLabComment{
				ProjectID: uint(tk.ProjectID),
				IssueIID:  uint(tk.IssueID),
				Message:   errMsg,
			})
			if err != nil {
				utils.DebugPrint("CommentError", "query task result comment is failed"+err.Error())
			}
			// Ticket状态：失败
			err = tk.ValidateAndUpdateStatus(&dbo.Ticket{
				UID:      tk.UID,
				AuthorID: tk.AuthorID,
			}, common.FailedStatus)
			if err != nil {
				return utils.GenerateError("TicketErr", err.Error())
			}
			// break
			return nil
		}
	}
	// Ticket状态：成功
	err = tk.ValidateAndUpdateStatus(&dbo.Ticket{
		UID:      tk.UID,
		AuthorID: tk.AuthorID,
	}, common.CompletedStatus)
	if err != nil {
		return utils.GenerateError("TicketErr", err.Error())
	}

	// 获取任务组信息
	val, exist := core.QueryTaskMap.Get(tk.UID)
	if !exist {
		return utils.GenerateError("CacheNotExist", "gitlab issue cache is not exist")
	}
	IssueVal, ok := val.(*core.IssueQTaskV2)
	if !ok {
		return utils.GenerateError("IssueNotMatch", "gitlab issue task cache is not match")
	}

	//TODO:存储结果、输出结果临时链接
	uuKey, tempURL := glbapi.NewHashTempLink()
	tempResSrv := NewTempResultService(tk.AuthorID)
	err = tempResSrv.Insert(dto.TempResultDTO{
		UUKey:         uuKey,
		TaskID:        sqlResult.GID,
		TicketID:      tk.UID,
		IsAllowExport: IssueVal.QTG.IsExport,
	}, common.DefaultCacheMapDDL)
	// err = dbo.SaveTempResult(sqlResult.TicketID, uuKey, common.DefaultCacheMapDDL, IssueVal.QTG.IsExport)
	if err != nil {
		return err
	}
	err = glab.CommentCreate(glbapi.GitLabComment{
		ProjectID: uint(tk.ProjectID),
		IssueIID:  uint(tk.IssueID),
		Message:   tempURL,
	})
	if err != nil {
		utils.ErrorPrint("GitlabCommentErr", err.Error())
	}
	// 自动关闭issue（表示完成）
	// err = glab.IssueClose(v.IssProjectID, v.IssIID)
	// if err != nil {
	// 	utils.DebugPrint("GitLabAPIError", err.Error())
	// }

	// ! 通知
	srv.ProjectID = uint(tk.ProjectID)
	srv.IssueIID = uint(tk.IssueID)
	srv.UserID = tk.AuthorID
	srv.NotifyWX()
	return nil
}

// 接口方法
func (srv *GitLabTaskService) UpdateTicketStats(targetStats string, exceptStats ...string) error {
	tk := NewTicketService()
	return tk.UpdateTicketStats(dto.TicketDTO{
		AuthorID:  srv.UserID,
		ProjectID: uint(srv.ProjectID),
		IssueIID:  uint(srv.IssueIID),
	}, targetStats, exceptStats...)
}

// 存储预检数据
func (srv *GitLabTaskService) SaveCheckData(ctx context.Context, preCheckVal *core.PreCheckResultGroup) error {
	//! 存储预检任务信息
	core.CheckTaskMap.Set(srv.UID, preCheckVal, common.DefaultCacheMapDDL, common.CheckTaskMapCleanFlag)

	val, exist := core.GitLabIssueMap.Get(srv.UID)
	if !exist {
		return utils.GenerateError("CachesNotExist", "Gitlab Issue Cache is not exist")
	}
	v, ok := val.(*IssueCache)
	if !ok {
		return utils.GenerateError("CachesNotMatch", "Gitlab Issue Cache Kind is not match")
	}

	// Gitlab Issue评论情况更新
	glab := glbapi.InitGitLabAPI()
	var updateMsg, title string
	if preCheckVal.IsDoubleCheck {
		title = "Double-Check"
	} else {
		title = "Frist-Check"
	}
	if preCheckVal.Errrr != nil {
		updateMsg = fmt.Sprintf("TicketID=%d \n%s Task is Failed\n- %s", preCheckVal.TicketID, title, preCheckVal.ErrMsg)
	} else {
		updateMsg = fmt.Sprintf("TicketID=%d \n%s Task is Success\n", preCheckVal.TicketID, title)
	}
	err := glab.CommentCreate(glbapi.GitLabComment{
		ProjectID: v.ProjectID,
		IssueIID:  v.Issue.IID,
		Message:   updateMsg,
	})
	if err != nil {
		utils.ErrorPrint("GitlabCommentErr", err.Error())
	}
	return nil
}

// ! 获取预检结果集(支持重新解析)
func getPreCheckResult(ctx context.Context, uid int64, redo ReExcute) (*core.PreCheckResultGroup, error) {
	var fristCheckVal *core.PreCheckResultGroup
	val, exist := core.CheckTaskMap.Get(uid)
	if !exist {
		if redo.IsReExcute {
			fmt.Println("debug print 开启重做...")
			redo.Fn()
			// 同步方式每秒检测是否查询任务完成，来获取结果集
			ticker := time.NewTicker(time.Duration(time.Second))
			defer ticker.Stop()
			// 超时控制
			timeout, cancel := context.WithTimeout(ctx, time.Duration(redo.Deadline))
			defer cancel()

			for {
				select {
				case <-ticker.C:
					mapVal, ok := core.CheckTaskMap.Get(uid)
					if !ok {
						continue
					}
					fristCheckVal, ok = mapVal.(*core.PreCheckResultGroup)
					if !ok {
						return nil, utils.GenerateError("PreCheckResultError", "pre-check result type is incorrect")
					}
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

// 企业微信通知详情
// TODO: 灵活设置更新消息以及对象
func (srv *GitLabTaskService) NotifyWX() {
	// 完成企业微信通知
	glab := clients.InitGitLabAPI()
	iss, err := glab.IssueView(srv.ProjectID, srv.IssueIID)
	if err != nil {
		utils.DebugPrint("GitLabAPIError", err.Error())
	}
	rob := wx.NewRobotNotice(&wx.InformTemplate{
		UserName: iss.Author.Name,
		Action:   "Completed",
		Link:     iss.WebURL,
	})
	err = rob.InformRobot()
	if err != nil {
		utils.ErrorPrint("InformFailed", err.Error())
	}
}

// GItLab评论通知
func (srv *GitLabTaskService) NotifyGitLab(msg string) {
	// GitLab Issue Comment
	glab := glbapi.InitGitLabAPI()
	retryErr := glab.Retry(3, func() error {
		return glab.CommentCreate(glbapi.GitLabComment{
			ProjectID: srv.ProjectID,
			IssueIID:  srv.IssueIID,
			Message:   msg,
		})
	})
	if retryErr != nil {
		utils.ErrorPrint("CommentFailed", retryErr.Error())
	}
}
