package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/utils"
	"strings"
	"time"
)

// 主要是封装一个操作GITLAB API的Handler
type GitLabAPI struct {
	URL         string
	AccessToken string
}
type GitLabComment struct {
	ProjectID uint
	IssueIID  uint
	AuthorID  uint
	Message   string
}

func InitGitLabAPI() *GitLabAPI {
	gitlabConfig := conf.GetAppConf().GetBaseConfig().GitLabEnv
	return &GitLabAPI{
		URL:         gitlabConfig.URL,
		AccessToken: gitlabConfig.AccessToken,
	}
}

// Gitlab Issue 响应体
type Issue struct {
	ID          uint   `json:"id"`
	IID         uint   `json:"iid"`
	Title       string `json:"title"`
	State       string `json:"state"` // opened、closed
	Description string `json:"description"`
	Assigneers  []uint `json:"assignee_ids"`
	CreateAt    string `json:"created_at"`
	UpdateAt    string `json:"updated_at"`
	DueDate     string `json:"due_date"`
	Author      GUser  `json:"author"`
	AuthorID    uint   `json:"author_id"`
	ProjectID   uint   `json:"project_id"`
	URL         string `json:"url"`     // Issue URL
	WebURL      string `json:"web_url"` // Issue URL
	Action      string `json:"action"`
}

type Comment struct {
	ID       uint   `json:"id"`
	Note     string `json:"note"`
	CreateAt string `json:"created_at"`
	UpdateAt string `json:"updated_at"`
	Action   string `json:"action"`
	AuthorID uint   `json:"author_id"`
}

// Issue创建者用户和GitLab Robot
type GUser struct {
	ID       uint   `json:"id"`
	Username string `json:"username"` // 理解为账号名
	Name     string `json:"name"`
	State    string `json:"state"`
	Email    string `json:"email"`
}

type Project struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// ! 封装GitLab API

// 带有重试次数评论装饰器
func (gitlab *GitLabAPI) Retry(times int, fn func() error) error {
	var err error
	for i := 0; i < times; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		fmt.Printf("GitLab 评论重试: %d 次", i+1)
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("GitLab Comment Retry is Failed %s", err.Error())
}

// 创建评论
func (gitlab *GitLabAPI) CommentCreate(body GitLabComment) error {
	reqBody := struct {
		Body     string `json:"body"`
		Internal bool   `json:"internal"`
		CreateAt string `json:"created_at"`
	}{
		Body: body.Message,
	}
	jsonData, err := json.Marshal(&reqBody)
	if err != nil {
		return utils.GenerateError("JSONError", err.Error())
	}
	commentCreateURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d/notes", body.ProjectID, body.IssueIID)
	req, err := http.NewRequest("POST", commentCreateURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return utils.GenerateError("CommentCreateError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	// 设置请求头，携带JSON形式的POST请求体
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return utils.GenerateError("CommentCreateError", err.Error())
	}
	defer resp.Body.Close()
	return common.ValidateRespBody("CommentCreateError", resp)
}

// 获取某个项目下的Issue详情
func (gitlab *GitLabAPI) IssueView(projectId, issueIId uint) (*Issue, error) {
	signalIssueURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d", projectId, issueIId)
	req, err := http.NewRequest("GET", signalIssueURL, nil)
	if err != nil {
		return nil, utils.GenerateError("IssueViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)

	// 构造并发起请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, utils.GenerateError("IssueViewError", err.Error())
	}
	defer resp.Body.Close()
	err = common.ValidateRespBody("IssueViewError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var i Issue
	err = json.NewDecoder(resp.Body).Decode(&i)
	if err != nil {
		return nil, utils.GenerateError("IssueViewError", err.Error())
	}
	return &i, nil
}

func (gitlab *GitLabAPI) IssueClose(projectId, issueIid uint) error {
	apiURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d", projectId, issueIid)
	// 序列化关闭问题的参数
	reqBody := struct {
		StateEvent string `json:"state_event"`
	}{
		StateEvent: "close",
	}
	jsonData, err := json.Marshal(&reqBody)
	if err != nil {
		return utils.GenerateError("JSONError", err.Error())
	}
	req, err := http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return utils.GenerateError("IssueCloseError", err.Error())
	}
	// 设置请求头，携带JSON形式的POST请求体
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return utils.GenerateError("IssueCloseError", err.Error())
	}
	defer resp.Body.Close()
	return common.ValidateRespBody("IssueCloseError", resp)
}

// 获取单个用户
func (gitlab *GitLabAPI) UserView(userId uint) (*GUser, error) {
	apiURL := gitlab.URL + fmt.Sprintf("/api/v4/users/%d", userId)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, utils.GenerateError("UserViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, utils.GenerateError("UserViewError", err.Error())
	}
	defer resp.Body.Close()
	err = common.ValidateRespBody("UserViewError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var u GUser
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		return nil, utils.GenerateError("UserViewError", err.Error())
	}
	return &u, nil
}

// 获取用户列表
func (gitlab *GitLabAPI) UserList() ([]GUser, error) {
	apiURL := gitlab.URL + "/api/v4/users"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, utils.GenerateError("GUserListError", err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, utils.GenerateError("GUserListError", err.Error())
	}
	defer resp.Body.Close()
	err = common.ValidateRespBody("GUserListError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var userList []GUser
	err = json.NewDecoder(resp.Body).Decode(&userList)
	if err != nil {
		return nil, utils.GenerateError("GUserListError", err.Error())
	}
	return userList, nil
}

// 生成临时链接
func NewHashTempLink() (string, string) {
	appConfig := conf.GetAppConf().GetBaseConfig()
	uuKey := utils.GenerateUUIDKey()
	// 导出链接组成
	tempResultURL := fmt.Sprintf("http://%s/result/temp-view/%s", appConfig.WebSrvEnv.HostName, uuKey)
	return uuKey, tempResultURL
}

// 解析Issue描述详情
func ParseIssueDesc(desc string) ([]byte, error) {
	// 解析issue的描述情况是否为代码块
	var descBytes []byte
	if strings.HasPrefix(desc, "```") && strings.HasSuffix(desc, "```") {
		temp := []byte(desc)
		length := len(temp)
		descBytes = temp[3 : length-3]
	} else {
		descBytes = []byte(desc)
	}
	// 格式化：正则替换换行符
	reg, err := regexp.Compile("\n")
	if err != nil {
		return nil, err
	}
	regResult := reg.ReplaceAll(descBytes, []byte(""))
	return regResult, nil
}
