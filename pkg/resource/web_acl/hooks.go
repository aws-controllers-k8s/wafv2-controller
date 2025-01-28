package web_acl

import (
	"github.com/ghodss/yaml"

	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/aws-sdk-go/aws"
)

type Statement interface {
	svcsdktypes.Statement | svcsdktypes.AndStatement | svcsdktypes.OrStatement | svcsdktypes.NotStatement
}

func statementToString[T Statement](cfg *T) (*string, error) {
	configBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	configStr := string(configBytes)
	return &configStr, nil
}

func stringToStatement[T Statement](cfg *string) (*T, error) {
	if cfg == nil {
		cfg = aws.String("")
	}

	var config T
	err := yaml.Unmarshal([]byte(*cfg), &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
