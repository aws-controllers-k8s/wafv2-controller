package rule_group

import (
	"bytes"
	"encoding/json"

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

// strictStatement decodes a nested statement and rejects unknown fields, so a
// misspelled or unsupported key is reported rather than silently dropped.
func strictStatement[T Statement](s *string) (*T, error) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(*s))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()

	var config T
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// canonicalizeNestedStatement round-trips a nested statement through its SDK
// shape so that two equivalent renderings of the same statement produce the same
// string. Input that does not decode cleanly is returned unchanged, which leaves
// plain string comparison in place so unsupported fields stay a visible delta.
func canonicalizeNestedStatement[T Statement](s *string) *string {
	if s == nil || *s == "" {
		return s
	}
	parsed, err := strictStatement[T](s)
	if err != nil {
		return s
	}
	canonical, err := statementToString(parsed)
	if err != nil {
		return s
	}
	return canonical
}

// canonicalizeRulesNestedStatements returns a deep copy of r whose nested
// statement strings are canonical. It copies rather than mutating because the
// desired resource is passed here, and rewriting its spec would persist the
// canonical rendering over what the user authored.
func canonicalizeRulesNestedStatements(r *resource) *resource {
	if r == nil || r.ko == nil || len(r.ko.Spec.Rules) == 0 {
		return r
	}
	ko := r.ko.DeepCopy()
	for _, rule := range ko.Spec.Rules {
		if rule == nil || rule.Statement == nil {
			continue
		}
		s := rule.Statement
		s.AndStatement = canonicalizeNestedStatement[svcsdktypes.AndStatement](s.AndStatement)
		s.OrStatement = canonicalizeNestedStatement[svcsdktypes.OrStatement](s.OrStatement)
		s.NotStatement = canonicalizeNestedStatement[svcsdktypes.NotStatement](s.NotStatement)
		if s.ManagedRuleGroupStatement != nil {
			s.ManagedRuleGroupStatement.ScopeDownStatement =
				canonicalizeNestedStatement[svcsdktypes.Statement](s.ManagedRuleGroupStatement.ScopeDownStatement)
		}
		if s.RateBasedStatement != nil {
			s.RateBasedStatement.ScopeDownStatement =
				canonicalizeNestedStatement[svcsdktypes.Statement](s.RateBasedStatement.ScopeDownStatement)
		}
	}
	return &resource{ko}
}
