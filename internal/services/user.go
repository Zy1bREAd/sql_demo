package services

import (
	"context"
	"encoding/json"
	"fmt"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/auth"
	clients "sql_demo/internal/clients/gitlab"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"

	"go.uber.org/zap"
)

type UserService struct {
	DAO dbo.User
}

func NewUserService() *UserService {
	return &UserService{
		DAO: dbo.User{},
	}
}

// 判断是否存在用户，并获取该Identity
func (srv *UserService) GetIDByIdentify(identify uint) string {
	user, err := srv.DAO.FindOne(&dbo.User{
		Kind:           2,
		GitLabIdentity: identify,
	})
	if err != nil {
		logger := core.GetLogger()
		logger.Error(err.Error(), zap.String("title", "UserSrvErr"))
		return ""
	}
	return user.ID
}

// 同步GitLab的用户 => 用户表（涉及到新增or更新）
func (srv *UserService) SyncGitLabUsers() error {
	glbAPI := clients.InitGitLabAPI()
	users, err := glbAPI.UserList()
	if err != nil {
		return err
	}
	for _, u := range users {
		shortUID := utils.GenerateUUIDKey()[:8]
		glbUser := dbo.User{
			ID:             shortUID,
			Name:           u.Name,
			UserName:       u.Username,
			Email:          u.Email,
			Kind:           common.GitLabUser,
			GitLabIdentity: u.ID,
			Status:         u.State,
			IsAdmin:        u.IsAdmin,
		}
		if u.State == "active" {
			glbUser.IsActive = true
		}
		err := srv.DAO.CreateOrUpdate(&glbUser)
		if err != nil {
			return err
		}
	}

	return nil
}

// SSO登录
func (srv *UserService) SSOLogin() (string, string, error) {
	oa2 := auth.GetOAuthConfig()
	state, err := auth.SetState()
	if err != nil {
		return "", "", utils.GenerateError("SSOLoginErr", err.Error())
	}
	authURL := oa2.AuthCodeURL(state)
	return authURL, state, nil
}

// SSO回调
func (srv *UserService) SSOCallBack(reqState, reqCode string) (*dto.SSOLoginDTO, error) {
	// 避免伪造SSO请求
	c := common.GetKVCache()
	cKey := fmt.Sprintf("%s:%s", common.SessionPrefix, reqState)
	_, exist := c.RistCache.Get(cKey)
	if !exist {
		return nil, utils.GenerateError("SSOCallBackErr", "State parameter is not exist")
	}
	// 清理缓存
	defer c.RistCache.Del(cKey)

	// 获取授权码转成Token
	oa2 := auth.GetOAuthConfig()
	ctx := context.Background()
	token, err := oa2.Exchange(ctx, reqCode)
	if err != nil {
		return nil, utils.GenerateError("SSOCallBackErr", "Exchange Token is Failed "+err.Error())
	}

	// 置换Token：通过获取身份提供商的token中的用户信息，构造我们application的token
	oauthConf := auth.GetOAuthConfig()
	client := oauthConf.Client(ctx, token)
	appConf := conf.GetAppConf().BaseConfig()

	resp, err := client.Get(appConf.SSOEnv.ClientAPI)
	if err != nil {
		return nil, utils.GenerateError("SSOCallBackErr", "Request client is failed "+err.Error())
	}
	defer resp.Body.Close()

	var oauthUser clients.GUser
	err = json.NewDecoder(resp.Body).Decode(&oauthUser)
	if err != nil {
		return nil, utils.GenerateError("SSOCallBackErr", "JSON Parsed is  failed "+err.Error())
	}

	// 若存在更新记录；反之，直接报错。
	loginUser := dbo.User{
		GitLabIdentity: oauthUser.ID,
		Kind:           common.GitLabUser,
		Name:           oauthUser.Name,
		UserName:       oauthUser.Username,
		Email:          oauthUser.Email,
		IsAdmin:        oauthUser.IsAdmin,
		Status:         oauthUser.State,
	}
	if oauthUser.State == "active" {
		loginUser.IsActive = true
	}

	uid, err := srv.DAO.SSOLogin(&loginUser)
	if err != nil {
		return nil, utils.GenerateError("SSOCallBackErr", err.Error())
	}
	// 生成JWT
	appToken, err := auth.GenerateJWT(uid, loginUser.Name, loginUser.Email, loginUser.Kind)
	if err != nil {
		return nil, utils.GenerateError("SSOCallBackErr", err.Error())
	}
	return &dto.SSOLoginDTO{
		Token: appToken,
		UserDTO: dto.UserDTO{
			Kind:     loginUser.Kind,
			Name:     loginUser.Name,
			UserName: loginUser.UserName,
			Email:    loginUser.Email,
			Status:   loginUser.Status,
			UID:      uid,
		},
	}, nil
}
