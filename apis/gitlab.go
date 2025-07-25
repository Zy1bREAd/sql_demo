package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// 主要是封装一个操作GITLAB API的Handler
type GitLabAPI struct {
	URL         string
	AccessToken string
}

func InitGitLabAPI() *GitLabAPI {
	gitlabConfig := GetAppConfig().GitLabEnv
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

// 创建评论
func (gitlab *GitLabAPI) CommentCreate(projectId, issueIId uint, content string) error {
	reqBody := struct {
		Body     string `json:"body"`
		Internal bool   `json:"internal"`
		CreateAt string `json:"created_at"`
	}{
		Body: content,
	}
	jsonData, err := json.Marshal(&reqBody)
	if err != nil {
		return GenerateError("JSONError", err.Error())
	}
	commentCreateURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d/notes", projectId, issueIId)
	req, err := http.NewRequest("POST", commentCreateURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return GenerateError("CommentCreateError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	// 设置请求头，携带JSON形式的POST请求体
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return GenerateError("CommentCreateError", err.Error())
	}
	defer resp.Body.Close()
	return ValidateRespBody("CommentCreateError", resp)
}

// 获取某个项目下的Issue详情
func (gitlab *GitLabAPI) IssueView(projectId, issueIId uint) (*Issue, error) {
	signalIssueURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d", projectId, issueIId)
	req, err := http.NewRequest("GET", signalIssueURL, nil)
	if err != nil {
		return nil, GenerateError("IssueViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, GenerateError("IssueViewError", err.Error())
	}
	defer resp.Body.Close()
	err = ValidateRespBody("IssueViewError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var i Issue
	err = json.NewDecoder(resp.Body).Decode(&i)
	if err != nil {
		return nil, GenerateError("IssueViewError", err.Error())
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
		return GenerateError("JSONError", err.Error())
	}
	req, err := http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return GenerateError("IssueCloseError", err.Error())
	}
	// 设置请求头，携带JSON形式的POST请求体
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return GenerateError("IssueCloseError", err.Error())
	}
	defer resp.Body.Close()
	return ValidateRespBody("IssueCloseError", resp)
}

// 获取单个用户
func (gitlab *GitLabAPI) UserView(userId uint) (*GUser, error) {
	apiURL := gitlab.URL + fmt.Sprintf("/api/v4/users/%d", userId)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, GenerateError("UserViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, GenerateError("UserViewError", err.Error())
	}
	defer resp.Body.Close()
	err = ValidateRespBody("UserViewError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var u GUser
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		return nil, GenerateError("UserViewError", err.Error())
	}
	return &u, nil
}

// 获取用户列表
func (gitlab *GitLabAPI) UserList() ([]GUser, error) {
	apiURL := gitlab.URL + "/api/v4/users"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, GenerateError("UserListError", err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, GenerateError("UserListError", err.Error())
	}
	defer resp.Body.Close()
	err = ValidateRespBody("IssueCloseError", resp)
	if err != nil {
		return nil, err
	}
	// 反序列化
	var userList []GUser
	err = json.NewDecoder(resp.Body).Decode(&userList)
	if err != nil {
		return nil, GenerateError("UserViewError", err.Error())
	}
	return userList, nil
}

// 生成临时链接
func NewHashTempLink() (string, string) {
	appConfig := GetAppConfig()
	uuKey := GenerateUUIDKey()
	tempResultURL := fmt.Sprintf("http://%s/result/temp-view/%s", appConfig.WebSrvEnv.HostName, uuKey)
	return uuKey, tempResultURL
}
