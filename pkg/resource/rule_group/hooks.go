package rule_group

import (
	"github.com/ghodss/yaml"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/wafv2"
)

type Statement interface {
	svcsdk.Statement | svcsdk.AndStatement | svcsdk.OrStatement | svcsdk.NotStatement
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
