package apis

import (
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
	Assigneer   string `json:"assignee"`
	CreateAt    string `json:"created_at"`
	UpdateAt    string `json:"updated_at"`
	AuthorID    uint   `json:"author_id"`
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

// 封装API
func (gitlab *GitLabAPI) CommentCreate(projectId, issueIId uint, content string) error {
	commentCreateURL := gitlab.URL + fmt.Sprintf("/api/v4/projects/%d/issues/%d/notes?body=%s", projectId, issueIId, content)
	req, err := http.NewRequest("POST", commentCreateURL, nil)
	if err != nil {
		return GenerateError("IssueViewError", err.Error())
	}
	req.Header.Set("PRIVATE-TOKEN", gitlab.AccessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return GenerateError("IssueViewError", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.StatusCode, resp)
		return GenerateError("IssueViewError", "not 200")
	}
	return nil
}

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
	fmt.Println("issue view result:", i)
	return &i, nil
}
