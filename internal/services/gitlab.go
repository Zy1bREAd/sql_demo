package services

import (
	"errors"
	"fmt"
	"slices"
	clients "sql_demo/internal/clients/gitlab"
	wx "sql_demo/internal/clients/weixin"
	"sql_demo/internal/conf"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

// 缓存结构体(组合优于继承)
type IssueCache struct {
	*clients.Issue
	Content *SQLIssueTemplate
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
	baseConf := conf.GetAppConf().GetBaseConfig()
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

// 仅用于调用API, 其余事情由事件驱动者完成
func (i *IssueWebhook) OpenIssueHandle() error {
	// 区分Issue是open还是update操作,企业微信通知,发送消息通知至企业微信机器人
	issueActionMap := map[string]int{
		"open":   IssueOpenFlag,
		"update": IssueUpdateFlag,
	}
	// 初始化
	var issContent *SQLIssueTemplate
	ep := event.GetEventProducer()

	switch i.ObjectAttr.Action {
	case "open":
		descBytes, err := clients.ParseIssueDesc(i.ObjectAttr.Description)
		if err != nil {
			utils.DebugPrint("ParseError", err.Error())
			return err
		}
		issDesc, err := ParseIssueTemplate(descBytes)
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
					Issue:  &i.ObjectAttr,
					Action: issueActionMap[i.ObjectAttr.Action],
					Desc:   issContent,
				},
			},
		})
	case "update":
		desc, exist := i.Changes["description"]
		if exist {
			// 仅针对Issue详情内容修改的检测
			if _, ok := desc.Current.(string); ok {
				// 解析Issue详情内容
				descBytes, err := clients.ParseIssueDesc(i.ObjectAttr.Description)
				if err != nil {
					utils.DebugPrint("ParseError", err.Error())
					return err
				}
				issDesc, err := ParseIssueTemplate(descBytes)
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
							Issue:  &i.ObjectAttr,
							Action: issueActionMap[i.ObjectAttr.Action],
							Desc:   issContent,
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
	approvalUserMap := conf.GetAppConf().GetBaseConfig().ApprovalMap
	approverID, exist := approvalUserMap[c.User.Name]
	if !exist {
		return utils.GenerateError("ApprovalUserNotExist", "该用户不是审批人")
	}
	if c.User.ID != approverID {
		// error: 不相同的userid
		return utils.GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
	}
	// 确认签派给SQL Handle User
	gitlabConfig := conf.GetAppConf().GetBaseConfig().GitLabEnv
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
	issDesc, err := ParseIssueTemplate(descBytes)
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
					Issue: &c.Issue,
					Desc:  issDesc,
				},
			},
		},
	})
	return nil
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
	glab := clients.InitGitLabAPI()
	// 驳回
	err := glab.CommentCreate(clients.GitLabComment{
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
	// 同意申请
	glab := clients.InitGitLabAPI()
	// 检查审批人是否合法
	approvalUserMap := conf.GetAppConf().GetBaseConfig().ApprovalMap
	approverID, exist := approvalUserMap[c.User.Name]
	if !exist {
		return utils.GenerateError("ApprovalUserNotExist", "该用户不是审批人")
	}
	if c.User.ID != approverID {
		// error: 不相同的userid
		return utils.GenerateError("ApprovalUserNotMatch", "审批人疑是伪造用户")
	}
	// 确认签派给SQL Handle User
	gitlabConfig := conf.GetAppConf().GetBaseConfig().GitLabEnv
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
	issContent, err := ParseIssueTemplate(descBytes)
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
					Issue: &c.Issue,
					Desc:  issContent,
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
		return utils.GenerateError("ActionErr", "Unknown Action"+string(content.Approval))
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
	// Deadline int  `json:"deadline,omitempty"`
	LongTime       bool `json:"long_time"`
	IsExport       bool `json:"is_export"`
	IsSoarAnalysis bool `json:"is_soar"` // 是否需要Soar检测获取SQL建议
}

// 集成Webhook结构体
type GitLabWebhook struct {
	Webhook string // issue、comment
	Payload any
}

// 集成批准、驳回两大数据的结构体
type IssuePayload struct {
	Action int // open、update
	Issue  *clients.Issue
	Desc   *SQLIssueTemplate
}

// 评论结构体
type CommentPayload struct {
	Reason       string
	Action       int // approval、reject、online
	CommentDesc  *CommentWebhook
	IssuePayload *IssuePayload
}

// 反序列化
func ParseIssueTemplate(descContent []byte) (*SQLIssueTemplate, error) {
	var content SQLIssueTemplate
	err := json.Unmarshal(descContent, &content)
	if err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, utils.GenerateError("JSONParseError", "issue decription syntax error:::"+err.Error())
		}
		return nil, err
	}
	return &content, nil
}
