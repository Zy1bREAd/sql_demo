package apis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

type IssueWebhook struct {
	EventType  string                `json:"event_type"`
	User       GUser                 `json:"user"`
	ObjectAttr Issue                 `json:"object_attributes"`
	Project    Project               `json:"project"`
	Changes    map[string]ChangeInfo `json:"changes"` // 记录变更内容
}

type ChangeInfo struct {
	// 由于变更内容有uint有string，所以使用空接口代替
	Previous any `json:"previous"`
	Current  any `json:"current"`
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
	Action    string `json:"action"`
	Note      string `json:"description"`
	Statement string `json:"statement"`
	DBName    string `json:"db_name"`
}

// 评论内容
type CommentContent struct {
	Approval uint   `json:"approval"`
	Reason   string `json:"reason"`
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
	if len(i.ObjectAttr.Assigneers) == 0 {
		// 没有签派给robot，因此跳过
		return nil
	}
	// 区分Issue是open还是update操作,企业微信通知,发送消息通知至企业微信机器人
	switch i.ObjectAttr.Action {
	case "open":
		DebugPrint("OpenIssueHandle", "open open open")
		informBody := &TicketInformBody{
			TicketType:    "Ticket Create",
			TicketDueDate: i.ObjectAttr.DueDate,
			TicketDesc:    i.ObjectAttr.Description,
			TicketLink:    i.ObjectAttr.URL,
			UserName:      i.User.Username,
		}
		_ = InformRobot(informBody.Fill())
	case "update":
		DebugPrint("UpdateIssueHandle", "update issue")
		desc, exist := i.Changes["description"]
		if exist {
			if val, ok := desc.Current.(string); ok {
				informBody := &TicketInformBody{
					TicketType:    "Ticket Update",
					TicketDueDate: i.ObjectAttr.DueDate,
					TicketDesc:    val,
					TicketLink:    i.ObjectAttr.URL,
					UserName:      i.User.Username,
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
func queryHandle(statement, dbName string, userId uint, issue *Issue) {
	// 事件驱动：封装成Event推送到事件通道(v2.0)
	// task := CreateSQLQueryTask(statement, dbName, strconv.FormatUint(uint64(userId), 10))
	issueTask := CreateSQLQueryTaskWithIssue(statement, dbName, userId, issue)
	ep := GetEventProducer()
	ep.Produce(Event{
		Type:    "sql_query",
		Payload: issueTask,
	})
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
		DebugPrint("IsNotJSON", "comment is not JSON format, maybe is string"+err.Error())
		return nil
	}
	if content.Approval == 0 {
		// 同意
		approvalMap := GetAppConfig().ApprovalMap
		if v, exist := approvalMap[c.User.Name]; exist {
			if v == c.User.ID {
				// 确认签派给SQL Handler这个robot user
				gitlabConfig := GetAppConfig().GitLabEnv
				if !slices.Contains(c.Issue.Assigneers, gitlabConfig.RobotUserId) {
					// 评论Issue
					api := InitGitLabAPI()
					issueAuthor, _ := api.UserView(c.ObjectAttr.AuthorID)
					robotMsg := fmt.Sprintf("@%s未指派正确的Handler,请重新指派后再次审批", issueAuthor.Username)
					_ = api.CommentCreate(c.Project.ID, c.Issue.IID, robotMsg)
					return GenerateError("AssigneerNotMatch", "assigneer is not match robot user")
				}
				// 查找指定的Issue
				api := InitGitLabAPI()
				iss, err := api.IssueView(c.Project.ID, c.Issue.ID)
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
				switch taskType {
				case "query":
					queryHandle(issContent.Statement, issContent.DBName, iss.AuthorID, iss)
				case "excute":
				default:
					DebugPrint("NothingDo", "no match task type")
				}
			} else {
				// error: 不相同的userid
				return GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
			}
		}
		return GenerateError("ApprovalUserNotExist", "审批人不存在")
	} else if content.Approval == 1 {
		// 驳回
		gitlab := InitGitLabAPI()
		err := gitlab.CommentCreate(c.Project.ID, c.Issue.IID, "【驳回】你的SQL任务请求,原因:"+content.Reason)
		if err != nil {
			return GenerateError("RejectError", err.Error())
		}
		//  发送驳回通知给企业微信机器人
		api := InitGitLabAPI()
		issueAuthor, err := api.UserView(c.Issue.AuthorID)
		if err != nil {
			return GenerateError("UserViewAPI", err.Error())
		}
		informBody := &RejectInformBody{
			TicketType: "Ticket Reject",
			TicketLink: c.Issue.URL,
			UserName:   issueAuthor.Username,
			Reason:     content.Reason,
			Approver:   c.User.Username,
		}
		InformRobot(informBody.Fill())
	}

	return nil
}
