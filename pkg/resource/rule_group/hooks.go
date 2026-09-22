package rule_group

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ghodss/yaml"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"k8s.io/apimachinery/pkg/api/equality"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"

	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
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
// shape, normalising the values WAF rewrites server-side, so two spellings of
// the same statement produce the same string. Input that does not decode cleanly
// is returned unchanged, which leaves raw string comparison in place so an
// unsupported field stays a visible delta.
func canonicalizeNestedStatement[T Statement](s *string) *string {
	if s == nil || *s == "" {
		return s
	}
	parsed, err := strictStatement[T](s)
	if err != nil {
		return s
	}
	normalizeNestedStatement(parsed)
	canonical, err := statementToString(parsed)
	if err != nil {
		return s
	}
	return canonical
}

// normalizeNestedStatement dispatches to the statement walker for each shape the
// CRD stores as a string.
func normalizeNestedStatement(v any) {
	switch t := v.(type) {
	case *svcsdktypes.Statement:
		normalizeStatement(t)
	case *svcsdktypes.AndStatement:
		for i := range t.Statements {
			normalizeStatement(&t.Statements[i])
		}
	case *svcsdktypes.OrStatement:
		for i := range t.Statements {
			normalizeStatement(&t.Statements[i])
		}
	case *svcsdktypes.NotStatement:
		normalizeStatement(t.Statement)
	}
}

// normalizeStatement rewrites, at any nesting depth, the values WAF normalises
// on read-back. Only SingleHeader.Name is known to be rewritten (WAF lowercases
// it); further normalisations belong in normalizeFieldToMatch beside it.
func normalizeStatement(s *svcsdktypes.Statement) {
	if s == nil {
		return
	}
	if s.ByteMatchStatement != nil {
		normalizeFieldToMatch(s.ByteMatchStatement.FieldToMatch)
	}
	if s.RegexMatchStatement != nil {
		normalizeFieldToMatch(s.RegexMatchStatement.FieldToMatch)
	}
	if s.RegexPatternSetReferenceStatement != nil {
		normalizeFieldToMatch(s.RegexPatternSetReferenceStatement.FieldToMatch)
	}
	if s.SizeConstraintStatement != nil {
		normalizeFieldToMatch(s.SizeConstraintStatement.FieldToMatch)
	}
	if s.SqliMatchStatement != nil {
		normalizeFieldToMatch(s.SqliMatchStatement.FieldToMatch)
	}
	if s.XssMatchStatement != nil {
		normalizeFieldToMatch(s.XssMatchStatement.FieldToMatch)
	}
	if s.AndStatement != nil {
		for i := range s.AndStatement.Statements {
			normalizeStatement(&s.AndStatement.Statements[i])
		}
	}
	if s.OrStatement != nil {
		for i := range s.OrStatement.Statements {
			normalizeStatement(&s.OrStatement.Statements[i])
		}
	}
	if s.NotStatement != nil {
		normalizeStatement(s.NotStatement.Statement)
	}
	if s.ManagedRuleGroupStatement != nil {
		normalizeStatement(s.ManagedRuleGroupStatement.ScopeDownStatement)
	}
	if s.RateBasedStatement != nil {
		normalizeStatement(s.RateBasedStatement.ScopeDownStatement)
	}
}

// normalizeFieldToMatch lowercases SingleHeader.Name, which WAF rewrites on
// read-back: header names are not case sensitive, so the service stores the
// lowercased form and a spec holding "Referer" never matches an observed
// "referer".
func normalizeFieldToMatch(f *svcsdktypes.FieldToMatch) {
	if f == nil || f.SingleHeader == nil || f.SingleHeader.Name == nil {
		return
	}
	lowered := strings.ToLower(*f.SingleHeader.Name)
	f.SingleHeader.Name = &lowered
}

// normalizeSpecStatement applies the same normalisation to the CRD's own typed
// statement fields, and canonicalises the members the CRD stores as strings.
func normalizeSpecStatement(s *svcapitypes.Statement) {
	if s == nil {
		return
	}
	if s.ByteMatchStatement != nil {
		normalizeSpecFieldToMatch(s.ByteMatchStatement.FieldToMatch)
	}
	if s.RegexMatchStatement != nil {
		normalizeSpecFieldToMatch(s.RegexMatchStatement.FieldToMatch)
	}
	if s.RegexPatternSetReferenceStatement != nil {
		normalizeSpecFieldToMatch(s.RegexPatternSetReferenceStatement.FieldToMatch)
	}
	if s.SizeConstraintStatement != nil {
		normalizeSpecFieldToMatch(s.SizeConstraintStatement.FieldToMatch)
	}
	if s.SQLIMatchStatement != nil {
		normalizeSpecFieldToMatch(s.SQLIMatchStatement.FieldToMatch)
	}
	if s.XSSMatchStatement != nil {
		normalizeSpecFieldToMatch(s.XSSMatchStatement.FieldToMatch)
	}
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

func normalizeSpecFieldToMatch(f *svcapitypes.FieldToMatch) {
	if f == nil || f.SingleHeader == nil || f.SingleHeader.Name == nil {
		return
	}
	lowered := strings.ToLower(*f.SingleHeader.Name)
	f.SingleHeader.Name = &lowered
}

// canonicalizeCopiedRules returns canonical copies of rules. It never mutates
// the input: the same objects are the merge-patch base the runtime persists, so
// rewriting them would replace the user's authored spec with the canonical form.
func canonicalizeCopiedRules(rules []*svcapitypes.Rule) []*svcapitypes.Rule {
	if rules == nil {
		return nil
	}
	out := make([]*svcapitypes.Rule, len(rules))
	for i, rule := range rules {
		if rule == nil {
			continue
		}
		copied := rule.DeepCopy()
		normalizeSpecStatement(copied.Statement)
		out[i] = copied
	}
	return out
}

// customPostCompareRules compares Spec.Rules, which the generated delta skips
// because the field is marked compare.is_ignored. It compares canonical copies
// so WAF's server-side normalisation never drives a spurious diff, and records
// the ORIGINAL values so the delta log shows what the user authored. A statement
// that fails to canonicalise keeps its raw string, so an unsupported field still
// produces a visible delta rather than being silently skipped.
func customPostCompareRules(delta *ackcompare.Delta, a, b *resource) {
	if a == nil || b == nil || a.ko == nil || b.ko == nil {
		return
	}
	if !equality.Semantic.DeepEqual(
		canonicalizeCopiedRules(a.ko.Spec.Rules),
		canonicalizeCopiedRules(b.ko.Spec.Rules),
	) {
		delta.Add("Spec.Rules", a.ko.Spec.Rules, b.ko.Spec.Rules)
	}
}
