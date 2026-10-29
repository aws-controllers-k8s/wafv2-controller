package rule_group

import (
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/api/equality"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
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

// customPreCompare compares Spec.Rules ignoring the *Ref fields, which sdkFind
// cannot rebuild from GetWebACL/GetRuleGroup. The resolved ARNs are still
// compared, so real drift is still detected.
func customPreCompare(delta *ackcompare.Delta, a, b *resource) {
	if !equality.Semantic.DeepEqual(rulesWithoutRefs(a.ko.Spec.Rules), rulesWithoutRefs(b.ko.Spec.Rules)) {
		delta.Add("Spec.Rules", a.ko.Spec.Rules, b.ko.Spec.Rules)
	}
}

func rulesWithoutRefs(rules []*svcapitypes.Rule) []*svcapitypes.Rule {
	out := make([]*svcapitypes.Rule, len(rules))
	for i, r := range rules {
		if r == nil {
			continue
		}
		c := r.DeepCopy()
		if c.Statement != nil {
			if s := c.Statement.IPSetReferenceStatement; s != nil {
				s.IPSetRef = nil
			}
		}
		out[i] = c
	}
	return out
}
