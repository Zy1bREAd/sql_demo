package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	"sql_demo/internal/utils"
	"sync"

	"golang.org/x/oauth2"
)

type GitLabUser struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	UserName    string `json:"username"`
	State       string `json:"state"`
	Email       string `json:"email"`
	LastLoginAt string `json:"last_sign_in_at"`
}

var oauthConf *oauth2.Config
var oauthOnce sync.Once

// 生成安全的随机State参数
func generateSSOState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func InitOAuth2() {
	conf := conf.GetAppConf().GetBaseConfig()
	oauthOnce.Do(func() {
		oauthConf = &oauth2.Config{
			ClientID:     conf.SSOEnv.ClientEnv.ID,
			ClientSecret: conf.SSOEnv.ClientEnv.Secret,
			RedirectURL:  conf.SSOEnv.RedirectURL,
			Scopes:       []string{"read_user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.SSOEnv.EndpointEnv.AuthURL,
				TokenURL: conf.SSOEnv.EndpointEnv.TokenURL,
			}, // gitlab 提供商
		}
	})
}

func GetOAuthConfig() *oauth2.Config {
	if oauthConf == nil {
		panic(utils.GenerateError("OAuthConfigNotInit", "oauth config object is not inited"))
	}
	return oauthConf
}

func SetState() (string, error) {
	state, err := generateSSOState()
	if err != nil {
		return "", err
	}
	core.SessionMap.Set(state, struct{}{}, 300, 2)
	return state, nil
}
