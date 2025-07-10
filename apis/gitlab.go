package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
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
	AuthorID    uint   `json:"author_id"`
	ProjectID   uint   `json:"project_id"`
	URL         string `json:"url"` // Issue URL
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
	Username string `json:"username"`
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
		return GenerateError("IssueViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	// 设置请求头，携带JSON形式的POST请求体
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return GenerateError("IssueViewError", err.Error())
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode, resp)
	if slices.Contains([]int{
		http.StatusBadRequest,
		http.StatusNotAcceptable,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	}, resp.StatusCode) {
		return GenerateError("IssueViewError", "response status code is not 200")
	}
	return nil
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
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.StatusCode, resp)
		return nil, GenerateError("IssueViewError", "not 200")
	}
	// 反序列化
	var i Issue
	err = json.NewDecoder(resp.Body).Decode(&i)
	if err != nil {
		return nil, GenerateError("IssueViewError", err.Error())
	}
	return &i, nil
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
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.StatusCode, resp)
		return nil, GenerateError("UserViewError", "not 200")
	}
	// 反序列化
	var u GUser
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		return nil, GenerateError("UserViewError", err.Error())
	}
	return &u, nil
}
