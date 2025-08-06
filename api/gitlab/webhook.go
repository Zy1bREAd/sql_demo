package api

import (
	"fmt"
	"log"
	"slices"
	"sql_demo/api"
	"sql_demo/internal/conf"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"

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

// 评论内容
type CommentContent struct {
	Approval uint   `json:"approval"`
	Reason   string `json:"reason"`
}

// 关于Callback的请求预检
func PreCheckCallback(ctx *gin.Context, gitlabEvent string) error {
	baseConf := conf.GetAppConf().GetBaseConfig()
	// 校验请求，避免伪造
	event := ctx.GetHeader("X-Gitlab-Event")
	if event != gitlabEvent {
		return utils.GenerateError("RequestHeaderError", "event is not match")
	}
	instance := ctx.GetHeader("X-Gitlab-Instance")
	if instance != baseConf.GitLabEnv.URL {
		return utils.GenerateError("RequestHeaderError", "source instance is invalid")
	}
	secret := ctx.GetHeader("X-Gitlab-Token")
	if secret != baseConf.GitLabEnv.WebhookEnv.SceretToken {
		return utils.GenerateError("RequestHeaderError", "source instance is invalid")
	}
	return nil
}

func (i *IssueWebhook) OpenIssueHandle() error {
	// var content SQLIssueTemplate
	// err := json.Unmarshal([]byte(i.ObjectAttr.Description), &content)
	// if err != nil {
	// 	utils.DebugPrint("JSONError", err.Error())
	// 	return err
	// }
	// if len(i.ObjectAttr.Assigneers) == 0 {
	// 	// 没有签派给robot，因此跳过
	// 	return nil
	// }
	// 区分Issue是open还是update操作,企业微信通知,发送消息通知至企业微信机器人
	switch i.ObjectAttr.Action {
	case "open":
		utils.DebugPrint("OpenIssueHandle", "open open open")
		rob := api.NewRobotNotice(&api.TicketInformBody{
			Action:   "Create",
			Title:    i.ObjectAttr.Title,
			DueDate:  i.ObjectAttr.DueDate,
			Desc:     i.ObjectAttr.Description,
			Link:     i.ObjectAttr.URL,
			UserName: i.User.Username,
		})
		err := rob.InformRobot()
		if err != nil {
			utils.DebugPrint("InformError", err.Error())
		}
	case "update":
		utils.DebugPrint("UpdateIssueHandle", "update issue")
		desc, exist := i.Changes["description"]
		if exist {
			if _, ok := desc.Current.(string); ok {
				// 是否需要强制不能query转excute呢？？
				rob := api.NewRobotNotice(&api.TicketInformBody{
					Action:   "Create",
					Title:    i.ObjectAttr.Title,
					DueDate:  i.ObjectAttr.DueDate,
					Desc:     i.ObjectAttr.Description,
					Link:     i.ObjectAttr.URL,
					UserName: i.User.Username,
				})
				err := rob.InformRobot()
				if err != nil {
					utils.DebugPrint("InformError", err.Error())
				}
			}
		}
	default:
		fmt.Println("nothing to do")
		return nil
	}
	// 存储DB？？
	return nil
}

func (c *CommentWebhook) handleApprovalPassed() error {
	// 同意申请
	glab := InitGitLabAPI()
	// 检查审批人是否合法
	approvalUserMap := conf.GetAppConf().GetBaseConfig().ApprovalMap
	v, exist := approvalUserMap[c.User.Name]
	if !exist {
		return utils.GenerateError("ApprovalUserNotExist", "该用户不是审批人")
	}
	if v != c.User.ID {
		// error: 不相同的userid
		return utils.GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
	}
	// 确认签派给SQL Handle User
	gitlabConfig := conf.GetAppConf().GetBaseConfig().GitLabEnv
	if !slices.Contains(c.Issue.Assigneers, gitlabConfig.RobotUserId) {
		robotMsg := fmt.Sprintf("【指派错误】@%s 未指派正确的Handler,请重新指派后再次审批", c.Issue.Author.Username)
		err := glab.CommentCreate(c.Project.ID, c.Issue.IID, robotMsg)
		if err != nil {
			log.Println(err.Error())
		}
		return utils.GenerateError("AssigneerNotMatch", "assigneer is not match robot user")
	}
	// 解析指定Issue
	iss, err := glab.IssueView(c.Project.ID, c.Issue.IID)
	if err != nil {
		utils.DebugPrint("GitLabAPIError", err.Error())
		return err
	}
	// 检查issue状态是否关闭
	if iss.State == "closed" {
		return utils.GenerateError("IsClosed", "The issue was closed")
	}
	// 解析Issue详情
	issContent, err := ParseIssueDesc(iss.Description)
	if err != nil {
		utils.DebugPrint("ParseError", err.Error())
		return err
	}
	//设置默认超时时间
	if issContent.Deadline == 0 {
		issContent.Deadline = 60
	}
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "gitlab_webhook",
		Payload: &GitLabWebhook{
			WebhookType: "comment",
			Issue:       iss,
			Desc:        issContent,
		},
	})
	return nil
	// return issContent.queryHandle(userId, iss, issContent.Statement)
}

func (c *CommentWebhook) handleApprovalRejected(reason string) error {
	// 检查审批人是否合法
	approvalUserMap := conf.GetAppConf().GetBaseConfig().ApprovalMap
	v, exist := approvalUserMap[c.User.Name]
	if !exist {
		return utils.GenerateError("ApprovalUserNotExist", "该用户不是审批人")
	}
	if v != c.User.ID {
		// error: 不相同的userid
		return utils.GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
	}
	glab := InitGitLabAPI()
	// 驳回
	err := glab.CommentCreate(c.Project.ID, c.Issue.IID, "【审批不通过】驳回该SQL执行, 原因:"+reason)
	if err != nil {
		return utils.GenerateError("CommentError", err.Error())
	}
	//  发送驳回通知给企业微信机器人
	issueAuthor, err := glab.UserView(c.Issue.AuthorID)
	if err != nil {
		return utils.GenerateError("GitLabAPIError", err.Error())
	}
	rob := api.NewRobotNotice(&api.RejectInformBody{
		Action:   "Reject",
		Link:     c.Issue.URL,
		UserName: issueAuthor.Username,
		Reason:   reason,
		Approver: c.User.Username,
	})
	err = rob.InformRobot()
	if err != nil {
		utils.DebugPrint("InformError", err.Error())
	}
	return nil
}

func (c *CommentWebhook) CommentIssueHandle() error {
	var content CommentContent
	err := json.Unmarshal([]byte(c.ObjectAttr.Note), &content)
	if err != nil {
		utils.DebugPrint("IsNotJSON", "comment is not JSON format, maybe is string. "+c.ObjectAttr.Note)
		return nil
	}
	switch content.Approval {
	case ApprovalStatusPassed:
		return c.handleApprovalPassed()
	case ApprovalStatusRejected:
		return c.handleApprovalRejected(content.Reason)
	default:
		return utils.GenerateError("ApprovalError", "Unknown Approval Status")
	}
}

// 问题内容
type SQLIssueTemplate struct {
	Action    string `json:"action"`
	Remark    string `json:"remark,omitempty"`
	Env       string `json:"env"`
	Statement string `json:"statement"`
	DBName    string `json:"db_name"`
	Service   string `json:"service"`
	// DML       string `json:"dml"`
	Deadline int  `json:"deadline,omitempty"`
	IsExport bool `json:"is_export"`
}

type GitLabWebhook struct {
	WebhookType string
	Issue       *Issue
	Desc        *SQLIssueTemplate
}
