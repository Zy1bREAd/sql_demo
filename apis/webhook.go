package apis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

type IssueWebhook struct {
	EventType  string  `json:"event_type"`
	User       GUser   `json:"user"`
	ObjectAttr Issue   `json:"object_attributes"`
	Project    Project `json:"project"`
}

type CommentWebhook struct {
	EventType  string  `json:"event_type"`
	User       GUser   `json:"user"`
	ObjectAttr Comment `json:"object_attributes"`
	Project    Project `json:"project"`
	Issue      Issue   `json:"issue"`
}

// 问题内容
type IssueContent struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	Statement   string `json:"statement"`
	DBName      string `json:"db_name"`
}

// 评论内容
type CommentContent struct {
	Approval uint   `json:"approval"`
	Reason   string `json:"reason"`
}

type issueHandleFn func(string, string, uint) error

var issueHandlerMap map[string]issueHandleFn = map[string]issueHandleFn{
	"query":  queryHandle,
	"excute": excuteHandle,
}

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
	fmt.Println(">>>>", content)
	// 区分Issue是open还是update操作

	// 存储DB？？

	// 企业微信通知,发送消息通知至企业微信机器人
	InformRobot()
	return nil
}

// 查询SQL
func queryHandle(statement, dbName string, userId uint) error {
	// 事件驱动：封装成Event推送到事件通道(v2.0)
	task := CreateSQLQueryTask(statement, dbName, strconv.FormatUint(uint64(userId), 10))
	ep := GetEventProducer()
	ep.Produce(Event{
		Type:    "sql_query",
		Payload: task,
	})
	return nil
}

// 执行SQL
func excuteHandle(statement, dbName string, userId uint) error {
	DebugPrint("not supported", "not supported excute sql")
	return nil
}

func parseIssueDesc(desc string) (*IssueContent, error) {
	var content IssueContent
	err := json.Unmarshal([]byte(desc), &content)
	if err != nil {
		DebugPrint("JSONError", err.Error())
		return nil, err
	}
	return &content, nil
}

func (c *CommentWebhook) CommentIssueHandle() error {
	var content CommentContent
	err := json.Unmarshal([]byte(c.ObjectAttr.Note), &content)
	if err != nil {
		DebugPrint("IsNotJSON", "comment is not JSON format, maybe is string")
		return nil
	}
	if content.Approval == 0 {
		// 同意
		approvalMap := GetAppConfig().ApprovalMap
		if v, exist := approvalMap[c.User.Name]; exist {
			if v == c.User.ID {
				// 查找指定的Issue
				gitlab := InitGitLabAPI()
				iss, err := gitlab.IssueView(c.Project.ID, c.Issue.ID)
				if err != nil {
					DebugPrint("IssueViewAPIError", err.Error())
					return err
				}
				// 解析Issue
				issContent, err := parseIssueDesc(iss.Description)
				if err != nil {
					DebugPrint("ParseError", err.Error())
					return err
				}
				// 灵活执行问题处理函数（SQL查询or执行）
				taskType := strings.ToLower(issContent.Action)
				err = issueHandlerMap[taskType](issContent.Statement, issContent.DBName, iss.AuthorID)
				if err != nil {
					DebugPrint("IssueHandleError", err.Error())
					return err
				}
			}
			// error: 不相同的userid
			return GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
		}
		return GenerateError("ApprovalUserNotExist", "审批人不存在")
	} else if content.Approval == 1 {
		// 驳回
		gitlab := InitGitLabAPI()
		err := gitlab.CommentCreate(c.Project.ID, c.Issue.IID, "驳回你的SQL任务请求,"+content.Reason)
		if err != nil {
			return GenerateError("RejectError", err.Error())
		}
	}

	return nil
}
