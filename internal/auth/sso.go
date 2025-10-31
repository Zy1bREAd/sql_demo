package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	"sql_demo/internal/utils"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

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
	c := core.GetKVCache()
	cKey := fmt.Sprintf("%s:%s", common.SessionPrefix, state)
	c.RistCache.SetWithTTL(cKey, struct{}{}, common.SmallItemCost, common.DefaultCacheMapDDL*time.Second)
	return state, nil
}
