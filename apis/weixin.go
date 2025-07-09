package apis

import "fmt"

func InformRobot() {
	informURL := GetAppConfig().WeixinEnv.InformWebhook
	fmt.Println(informURL)
}
