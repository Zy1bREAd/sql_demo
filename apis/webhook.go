package apis

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

// Issue问题事件的回调
type IssueWebhook struct {
	EventType  string                `json:"event_type"`
	User       GUser                 `json:"user"`
	ObjectAttr Issue                 `json:"object_attributes"`
	Project    Project               `json:"project"`
	Changes    map[string]ChangeInfo `json:"changes"` // 记录变更内容
}

// 变更记录
type ChangeInfo struct {
	// 由于变更内容有uint有string，所以使用空接口代替
	Previous any `json:"previous"`
	Current  any `json:"current"`
}

// 评论事件的回调
type CommentWebhook struct {
	EventType  string  `json:"event_type"`
	User       GUser   `json:"user"`
	ObjectAttr Comment `json:"object_attributes"`
	Project    Project `json:"project"`
	Issue      Issue   `json:"issue"`
}

// 问题内容
type IssueContent struct {
	Action    string `json:"action"`
	Note      string `json:"description"`
	Env       string `json:"env"`
	Statement string `json:"statement"`
	DBName    string `json:"db_name"`
	DML       string `json:"dml"`
	IsExport  bool   `json:"is_export"`
}

// 评论内容
type CommentContent struct {
	Approval uint   `json:"approval"`
	Reason   string `json:"reason"`
}

// 关于Callback的请求预检
func PreCheckCallback(ctx *gin.Context, gitlabEvent string) error {
	gitlabConfig := GetAppConfig()
	// 校验请求，避免伪造
	event := ctx.GetHeader("X-Gitlab-Event")
	if event != gitlabEvent {
		return GenerateError("RequestHeaderError", "event is not match")
	}
	instance := ctx.GetHeader("X-Gitlab-Instance")
	if instance != gitlabConfig.GitLabEnv.URL {
		return GenerateError("RequestHeaderError", "source instance is invalid")
	}
	secret := ctx.GetHeader("X-Gitlab-Token")
	if secret != gitlabConfig.GitLabEnv.WebhookEnv.SceretToken {
		return GenerateError("RequestHeaderError", "source instance is invalid")
	}
	return nil
}

func (i *IssueWebhook) OpenIssueHandle() error {
	var content IssueContent
	err := json.Unmarshal([]byte(i.ObjectAttr.Description), &content)
	if err != nil {
		DebugPrint("JSONError", err.Error())
		return err
	}
	if len(i.ObjectAttr.Assigneers) == 0 {
		// 没有签派给robot，因此跳过
		return nil
	}
	// 区分Issue是open还是update操作,企业微信通知,发送消息通知至企业微信机器人
	switch i.ObjectAttr.Action {
	case "open":
		DebugPrint("OpenIssueHandle", "open open open")
		informBody := &TicketInformBody{
			Action:   "Create",
			Title:    i.ObjectAttr.Title,
			DueDate:  i.ObjectAttr.DueDate,
			Desc:     i.ObjectAttr.Description,
			Link:     i.ObjectAttr.URL,
			UserName: i.User.Username,
		}
		_ = InformRobot(informBody.Fill())
	case "update":
		DebugPrint("UpdateIssueHandle", "update issue")
		desc, exist := i.Changes["description"]
		if exist {
			if _, ok := desc.Current.(string); ok {
				// 是否需要强制不能query转excute呢？？
				informBody := &TicketInformBody{
					Action:   "Update",
					DueDate:  i.ObjectAttr.DueDate,
					Title:    i.ObjectAttr.Title,
					Desc:     i.ObjectAttr.Description,
					Link:     i.ObjectAttr.URL,
					UserName: i.User.Username,
				}
				_ = InformRobot(informBody.Fill())
			}
		}
	default:
		fmt.Println("nothing to do")
		return nil
	}
	// 存储DB？？
	return nil
}

// 查询SQL
func queryHandle(userId uint, issue *Issue, issueDesc *IssueContent) {
	//! context控制超时
	issueTask := &IssueQueryTask{
		QTask: &QueryTask{
			ID:        GenerateUUIDKey(),
			DBName:    issueDesc.DBName,
			Statement: issueDesc.Statement,
			deadline:  30, // 抽离出来
			UserID:    userId,
			Env:       issueDesc.Env,
		},
		QIssue: issue,
	}
	ep := GetEventProducer()
	ep.Produce(Event{
		Type:    "sql_query",
		Payload: issueTask,
	})
	DebugPrint("TaskEnqueue", fmt.Sprintf("task id=%s is enqueue", issueTask.QTask.ID))
}

// 执行SQL
func excuteHandle(statement, dbName string, userId uint) error {
	DebugPrint("not supported", "not supported excute sql")
	return nil
}

// 解析Issue描述详情
func parseIssueDesc(desc string) (*IssueContent, error) {
	var content IssueContent
	err := json.Unmarshal([]byte(desc), &content)
	if err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, GenerateError("JSONParseError", "issue decription syntax error")
		}
		return nil, err
	}
	return &content, nil
}

func (c *CommentWebhook) CommentIssueHandle() error {
	var content CommentContent
	err := json.Unmarshal([]byte(c.ObjectAttr.Note), &content)
	if err != nil {
		DebugPrint("IsNotJSON", "comment is not JSON format, maybe is string. "+c.ObjectAttr.Note)
		return nil
	}
	api := InitGitLabAPI()
	if content.Approval == 0 {
		// 同意
		approvalMap := GetAppConfig().ApprovalMap
		v, exist := approvalMap[c.User.Name]
		if !exist {
			return GenerateError("ApprovalUserNotExist", "审批人不存在")
		}
		if v != c.User.ID {
			// error: 不相同的userid
			return GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
		}
		// 确认签派给SQL Handler这个robot user
		gitlabConfig := GetAppConfig().GitLabEnv
		if !slices.Contains(c.Issue.Assigneers, gitlabConfig.RobotUserId) {
			// 评论Issue
			robotMsg := fmt.Sprintf("【指派错误】@%s 未指派正确的Handler,请重新指派后再次审批", c.Issue.Author.Username)
			_ = api.CommentCreate(c.Project.ID, c.Issue.IID, robotMsg)
			return GenerateError("AssigneerNotMatch", "assigneer is not match robot user")
		}
		// 查找指定的Issue
		iss, err := api.IssueView(c.Project.ID, c.Issue.IID)
		if err != nil {
			DebugPrint("GitLabAPI", err.Error())
			return err
		}
		// 检查issue状态是否关闭
		if iss.State == "closed" {
			return GenerateError("IsClosed", "The issue was closed")
		}
		// 解析Issue
		issContent, err := parseIssueDesc(iss.Description)
		if err != nil {
			DebugPrint("ParseError", err.Error())
			return err
		}
		// 检查DML是否对齐SQL语句开头
		if !strings.HasPrefix(strings.ToLower(issContent.Statement), strings.ToLower(issContent.DML)) {
			return GenerateError("NotMatchError", "DML and Statement is not match")
		}
		// 灵活执行问题处理函数（SQL查询or执行）
		taskType := strings.ToLower(issContent.Action)
		switch taskType {
		case "query":
			// 获取真正的userId
			userId := GetUserId(iss.Author.ID)
			queryHandle(userId, iss, issContent)
		case "excute":
		default:
			DebugPrint("NothingDo", "no match task type")
		}
	} else if content.Approval == 1 {
		// 驳回
		err := api.CommentCreate(c.Project.ID, c.Issue.IID, "【审批不通过】驳回该SQL执行, 原因:"+content.Reason)
		if err != nil {
			return GenerateError("RejectError", err.Error())
		}
		//  发送驳回通知给企业微信机器人
		issueAuthor, err := api.UserView(c.Issue.AuthorID)
		if err != nil {
			return GenerateError("GitLabAPI", err.Error())
		}
		informBody := &RejectInformBody{
			Action:   "Reject",
			Link:     c.Issue.URL,
			UserName: issueAuthor.Username,
			Reason:   content.Reason,
			Approver: c.User.Username,
		}
		_ = InformRobot(informBody.Fill())
	}

	return nil
}
