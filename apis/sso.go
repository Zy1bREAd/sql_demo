package apis

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"golang.org/x/oauth2"
)

var oauthConf *oauth2.Config
var oauthOnce sync.Once

// 存储State参数的Map
var SessionMap *CachesMap = &CachesMap{cache: &sync.Map{}}

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
	conf := GetAppConfig()
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
		InitOAuth2()
	}
	return oauthConf
}

func SetState() (string, error) {
	state, err := generateSSOState()
	if err != nil {
		return "", err
	}
	SessionMap.Set(state, struct{}{}, 300, 2)
	return state, nil
}
