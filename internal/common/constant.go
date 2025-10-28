package common

// 任务类型
const (
	APITaskType    = 1
	GitLabTaskType = 2

	APISourceFlag    = 1
	GitLabSourceFlag = 2
)

const (
	ResultPrefix  = "result"
	SessionPrefix = "session"
	SQLTaskPrefix = "sql-task"
	// ExportTaskPrefix  = "export-task"
	CheckTaskPrefix   = "check-task"
	GitLabIssuePreifx = "gitlab-issue-body"
	APITaskBodyPrefix = "api-task-body"
)

const (
	SmallItemCost  = 10   // < 1KB
	MediumItemCost = 100  // 1KB - 10KB
	LargeItemCost  = 1000 // > 10KB
)

// Deadline
const (
	SelectDDL     = 90  // 默认查询为90秒、其他为300秒
	OtherDDL      = 300 // 默认查询为90秒、其他为300秒
	LongSelectDDL = 180
	LongOtherDDL  = 600

	DownloadFileDDL = 60

	// 默认CacheMap清理时间d
	FreeApprovalDDL    = 300   // 5min（免审批）
	DefaultCacheMapDDL = 600   // 10 min
	TicketCacheMapDDL  = 86400 // 1 day

	// CleanMap
	ResultMapCleanFlag      = 0
	QueryTaskMapCleanFlag   = 1
	SessionMapCleanFlag     = 2
	ExportWorkMapCleanFlag  = 3
	CheckTaskMapCleanFlag   = 4
	APITaskBodyMapCleanFlag = 5

	// TIMEOUT
	RetryTimeOut = 300
)

const (
	// Ticket Status
	CreatedStatus            = "CREATED"
	EditedStatus             = "EDITED"
	ReInitedStatus           = "REINITED" // 用于完成TIcket后二次更新Issue后的状态
	PreCheckingStatus        = "PRECHECKING"
	PreCheckSuccessStatus    = "PRECHECK_SUCCESS"
	PreCheckFailedStatus     = "PRECHECK_FAILED"
	ApprovalPassedStatus     = "APPROVAL_PASSED"
	ApprovalRejectStatus     = "APPROVAL_REJECT"
	OnlinePendingStatus      = "ONLINE_PENDING"
	OnlinePassedStatus       = "ONLINE_PASSED" // 审批成功，等待上线
	DoubleCheckingStatus     = "DOUBLECHECKING"
	DoubleCheckSuccessStatus = "DOUBLECHECK_SUCCESS"
	DoubleCheckFailedStatus  = "DOUBLECHECK_FAILED"
	ProcessingStatus         = "PROCESSING" // 执行任务中
	CompletedStatus          = "COMPLETED"
	FailedStatus             = "FAILED"
	UnknownStatus            = "UNKNOWN"

	// 数据源连接状态
	Connected     = 1
	ConnectFailed = 0
	Connecting    = 8
)

// Action标识
const (
	RejectActionFlag   = 0
	ApprovalActionFlag = 1
	OnlineActionFlag   = 2
)

// ! 封装响应数据
const (
	successCode = 200
	errorCode   = 500
)

// ! 封装App业务性的响应状态码
// 普通成功的都为个位数，错误通常都是两位数。
const (
	RespSuccess = 100
	RespFailed  = 11 // 未知错误的默认失败

	IllegalRequest      = 67
	NoPermissionRequest = 88

	RecordNotExist = 44
	RecordNotFound = 45
)

var ActionHandleMap map[int]string = map[int]string{
	RejectActionFlag:   "reject",
	ApprovalActionFlag: "approval",
	OnlineActionFlag:   "online",
}
