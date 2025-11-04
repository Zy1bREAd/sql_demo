package clients

import (
	"context"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	"sync"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"go.uber.org/zap"
)

type AIClient struct {
	Client openai.Client
	Model  string
}

type ChatResult struct {
	openai.ChatCompletion
}

var (
	aiClient AIClient
	once     sync.Once
)

func NewAIClient() (AIClient, error) {
	once.Do(func() {
		aiCfg := conf.GetAppConf().BaseConfig().AIEnv
		aiClient.Client = openai.NewClient(
			option.WithAPIKey(aiCfg.SecretKey),
			option.WithBaseURL(aiCfg.URL),
		)
		aiClient.Model = aiCfg.Model
	})
	return aiClient, nil
}

func (ai *AIClient) NewChat(ctx context.Context, question string) (*ChatResult, error) {
	chatCompletion, err := ai.Client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(question),
		},
		Model: ai.Model,
	})
	if err != nil {
		logger := core.GetLogger()
		logger.Error(err.Error(), zap.String("title", "AIChatErr"))
		return nil, err
	}
	return &ChatResult{
		ChatCompletion: *chatCompletion,
	}, err
}

func (res *ChatResult) StringResult() string {
	return res.ChatCompletion.Choices[0].Message.Content
}

func (res *ChatResult) JSONResult() string {
	return res.ChatCompletion.JSON.Choices.Raw()
}
