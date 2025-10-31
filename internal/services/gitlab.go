package services

import (
	"errors"
	"fmt"
	"slices"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/auth"
	clients "sql_demo/internal/clients/gitlab"
	wx "sql_demo/internal/clients/weixin"
	"sql_demo/internal/conf"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

// type IssueCache struct {
// 	*clients.Issue
// 	Content *SQLIssueTemplate
// 	action  int
// }

// 集成Webhook结构体
type GitLabWebhook struct {
	Webhook string // issue、comment
	Payload any
}

// IssueTask内容的结构体(组合优于继承)
type IssuePayload struct {
	*clients.Issue
	Content *dto.IssueTaskContent
	Action  int // open、update
}

// 评论结构体
type CommentPayload struct {
	Reason string
	Action int // approval、reject、online
	// CommentDesc  *CommentWebhook
	IssuePayload *IssuePayload
}

const (
	CommentOnlineExcute   = 2
	CommentApprovalPassed = 1
	CommentApprovalReject = -1

	IssueOpenFlag   = 1
	IssueUpdateFlag = 0

	IssueHandle   = "issue"
	CommentHandle = "comment"
)

// Issue问题事件的回调
type IssueWebhook struct {
	EventType  string             `json:"event_type"`
	User       clients.GUser      `json:"user"`
	ObjectAttr clients.Issue      `json:"object_attributes"`
	Project    clients.Project    `json:"project"`
	Changes    map[string]Changes `json:"changes"` // 记录变更内容
}

// 变更记录
type Changes struct {
	// 由于变更内容有uint有string，所以使用空接口代替
	Previous any `json:"previous"`
	Current  any `json:"current"`
}

// 评论事件的回调
type CommentWebhook struct {
	EventType  string          `json:"event_type"`
	User       clients.GUser   `json:"user"`
	ObjectAttr clients.Comment `json:"object_attributes"`
	Project    clients.Project `json:"project"`
	Issue      clients.Issue   `json:"issue"`
}

// 评论内容
type CommentContent struct {
	Approval int    `json:"approval"`
	Online   int    `json:"online"`
	Reason   string `json:"reason"`
}

// 关于Callback的请求预检
func PreCheckCallback(ctx *gin.Context, gitlabEvent string) error {
	baseConf := conf.GetAppConf().BaseConfig()
	// 校验请求，避免伪造
	event := ctx.GetHeader("X-Gitlab-Event")

	if !strings.HasSuffix(event, gitlabEvent) {
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

// 解析gitlab并进入gitlab event驱动流程
func (i *IssueWebhook) OpenIssueHandle() error {
	// 区分Issue是open还是update操作,企业微信通知,发送消息通知至企业微信机器人
	issueActionMap := map[string]int{
		"open":   IssueOpenFlag,
		"update": IssueUpdateFlag,
	}
	// 初始化
	var issContent *dto.IssueTaskContent
	ep := event.GetEventProducer()

	switch i.ObjectAttr.Action {
	// 打开一个新的Issue
	case "open":
		descBytes, err := clients.ParseIssueDesc(i.ObjectAttr.Description)
		if err != nil {
			utils.DebugPrint("ParseError", err.Error())
			return err
		}
		issDesc, err := ParseTaskContent(descBytes)
		if err != nil {
			return err
		}
		issContent = issDesc
		utils.DebugPrint("OpenIssueHandle", "open new a issue")
		rob := wx.NewRobotNotice(&wx.TicketInformBody{
			Action:   "Create",
			Title:    i.ObjectAttr.Title,
			DueDate:  i.ObjectAttr.DueDate,
			Desc:     i.ObjectAttr.Description,
			Link:     i.ObjectAttr.URL,
			UserName: i.User.Username,
		})
		// 发送消息给通知机器人
		err = rob.InformRobot()
		if err != nil {
			utils.DebugPrint("InformError", err.Error())
		}
		// 事件驱动下一阶段
		ep.Produce(event.Event{
			Type: "gitlab_webhook",
			Payload: &GitLabWebhook{
				Webhook: IssueHandle,
				Payload: &IssuePayload{
					Action:  issueActionMap[i.ObjectAttr.Action],
					Issue:   &i.ObjectAttr,
					Content: issContent,
				},
			},
		})

	// 编辑更新一个Issue
	case "update":
		desc, exist := i.Changes["description"]
		// 仅针对Issue详情内容修改的检测
		if exist {
			if _, ok := desc.Current.(string); ok {
				// 解析Issue详情内容
				descBytes, err := clients.ParseIssueDesc(i.ObjectAttr.Description)
				if err != nil {
					utils.DebugPrint("ParseError", err.Error())
					return err
				}
				issDesc, err := ParseTaskContent(descBytes)
				if err != nil {
					return err
				}
				issContent = issDesc
				rob := wx.NewRobotNotice(&wx.TicketInformBody{
					Action:   "Update",
					Title:    i.ObjectAttr.Title,
					DueDate:  i.ObjectAttr.DueDate,
					Desc:     i.ObjectAttr.Description,
					Link:     i.ObjectAttr.URL,
					UserName: i.User.Username,
				})
				// 发送消息给通知机器人
				err = rob.InformRobot()
				if err != nil {
					utils.DebugPrint("InformError", err.Error())
				}
				// 事件驱动下一阶段
				ep.Produce(event.Event{
					Type: "gitlab_webhook",
					Payload: &GitLabWebhook{
						Webhook: IssueHandle,
						Payload: &IssuePayload{
							Issue:   &i.ObjectAttr,
							Action:  issueActionMap[i.ObjectAttr.Action],
							Content: issContent,
						},
					},
				})
			}
		}
	default:
		// 检查是否为Issue关闭状态：
		utils.DebugPrint("UnknownErr", i.ObjectAttr.Action)
	}
	return nil
}

func (c *CommentWebhook) handleApprovalPassed() error {
	// 同意申请
	glab := clients.InitGitLabAPI()
	// 检查审批人是否合法
	permission := auth.GetCasbin()
	ok, err := permission.Enforce(c.User.Username, "sql-task", "approval")
	if err != nil {
		return utils.GenerateError("CasbinError", err.Error())
	}
	if !ok {
		return utils.GenerateError("ApprovalError", "permission denied")
	}
	// 确认签派给SQL Handle User
	gitlabConfig := conf.GetAppConf().BaseConfig().GitLabEnv
	if !slices.Contains(c.Issue.Assigneers, gitlabConfig.RobotUserId) {
		robotMsg := fmt.Sprintf("【指派错误】@%s 未指派正确的Handler,请重新指派后再次审批", c.Issue.Author.Username)
		return utils.GenerateError("AssigneerNotMatch", robotMsg)
	}
	// 解析指定Issue
	iss, err := glab.IssueView(c.Project.ID, c.Issue.IID)
	if err != nil {
		return utils.GenerateError("ParseIssueErr", err.Error())
	}
	// 检查issue状态是否关闭
	if strings.ToLower(iss.State) == "closed" {
		return utils.GenerateError("IssueClosed", "Issue已关闭")
	}
	// 解析Issue详情
	descBytes, err := clients.ParseIssueDesc(iss.Description)
	if err != nil {
		utils.DebugPrint("ParseError", err.Error())
		return err
	}
	issDesc, err := ParseTaskContent(descBytes)
	if err != nil {
		return err
	}

	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "gitlab_webhook",
		Payload: &GitLabWebhook{
			Webhook: CommentHandle,
			Payload: &CommentPayload{
				Action: CommentApprovalPassed,
				IssuePayload: &IssuePayload{
					Issue:   &c.Issue,
					Content: issDesc,
				},
			},
		},
	})
	return nil
}

func (c *CommentWebhook) handleApprovalRejected(reason string) error {
	glab := clients.InitGitLabAPI()
	// 检查审批人是否合法
	permission := auth.GetCasbin()
	ok, err := permission.Enforce(c.User.Username, "sql-task", "approval")
	if err != nil {
		return utils.GenerateError("CasbinError", err.Error())
	}
	if !ok {
		return utils.GenerateError("ApprovalError", "permission denied")
	}
	// 驳回
	err = glab.CommentCreate(clients.GitLabComment{
		ProjectID: c.Project.ID,
		IssueIID:  c.Issue.IID,
		Message:   "【审批不通过】驳回该SQL执行, 原因:" + reason,
	})
	if err != nil {
		return utils.GenerateError("CommentError", err.Error())
	}
	//  发送驳回通知给企业微信机器人
	issueAuthor, err := glab.UserView(c.Issue.AuthorID)
	if err != nil {
		return utils.GenerateError("GitLabAPIError", err.Error())
	}
	rob := wx.NewRobotNotice(&wx.RejectInformBody{
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

	// 进入Webhook其他操作
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "gitlab_webhook",
		Payload: &GitLabWebhook{
			Webhook: CommentHandle,
			Payload: &CommentPayload{
				Action: CommentApprovalReject,
				Reason: reason,
				IssuePayload: &IssuePayload{
					Issue: &c.Issue,
				},
			},
		},
	})
	return nil
}

func (c *CommentWebhook) handleOnlineExcute() error {
	// 检查审批人是否合法
	permission := auth.GetCasbin()
	ok, err := permission.Enforce(c.User.Username, "sql-task", "approval")
	if err != nil {
		return utils.GenerateError("CasbinError", err.Error())
	}
	if !ok {
		return utils.GenerateError("ApprovalError", "permission denied")
	}
	// 确认签派给SQL Handle User
	gitlabConfig := conf.GetAppConf().BaseConfig().GitLabEnv
	if !slices.Contains(c.Issue.Assigneers, gitlabConfig.RobotUserId) {
		robotMsg := fmt.Sprintf("【指派错误】@%s 未指派正确的Handler,请重新指派后再次审批", c.Issue.Author.Username)
		return utils.GenerateError("AssigneerNotMatch", robotMsg)
	}
	gitlabSrv := NewGitLabTaskService(
		WithGitLabTaskProjectID(c.Project.ID),
		WithGitLabTaskIssueIID(c.Issue.IID),
	)
	// 解析指定Issue
	issPayload, err := gitlabSrv.ParseIssue()
	if err != nil {
		return err
	}

	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "gitlab_webhook",
		Payload: &GitLabWebhook{
			Webhook: CommentHandle,
			Payload: &CommentPayload{
				Action: CommentOnlineExcute,
				IssuePayload: &IssuePayload{
					Issue:   &c.Issue,
					Content: issPayload.Content,
				},
			},
		},
	})
	return nil
}

func (c *CommentWebhook) CommentIssueHandle() error {
	var content CommentContent
	err := json.Unmarshal([]byte(c.ObjectAttr.Note), &content)
	if err != nil {
		utils.DebugPrint("IsNotJSON", "comment is not JSON format, maybe is string. "+c.ObjectAttr.Note)
		return nil
	}
	// 控制分支
	if content.Approval == CommentApprovalReject {
		return c.handleApprovalRejected(content.Reason)
	} else if content.Approval == CommentApprovalPassed {
		return c.handleApprovalPassed()
	} else if content.Online == CommentOnlineExcute {
		return c.handleOnlineExcute()
	} else {
		utils.DebugPrint("Unknown Action = %d", content.Approval)
		return nil
	}
}

// 反序列化
func ParseTaskContent(descContent []byte) (*dto.IssueTaskContent, error) {
	var content dto.IssueTaskContent
	err := json.Unmarshal(descContent, &content)
	if err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, utils.GenerateError("JSONParseError", "issue decription syntax error - "+err.Error())
		}
		return nil, err
	}
	return &content, nil
}
