// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package web_acl

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"k8s.io/apimachinery/pkg/api/equality"

	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
)

// authoredAndStatement is the nested statement exactly as it appears in
// test/e2e/resources/web_acl_nested_statement.yaml.
const authoredAndStatement = `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
      forwardedIPConfig:
        headerName: "X-Forwarded-For"
        fallbackBehavior: MATCH
  - notStatement:
      statement:
        byteMatchStatement:
          fieldToMatch:
            singleHeader:
              name: "Referer"
          positionalConstraint: EXACTLY
          searchString: c29tZXRoaW5n
          textTransformations:
            - type: NONE
              priority: 0
`

func sdkAndStatement(countryCodes ...svcsdktypes.CountryCode) *svcsdktypes.AndStatement {
	return &svcsdktypes.AndStatement{
		Statements: []svcsdktypes.Statement{
			{
				GeoMatchStatement: &svcsdktypes.GeoMatchStatement{
					CountryCodes: countryCodes,
					ForwardedIPConfig: &svcsdktypes.ForwardedIPConfig{
						HeaderName:       aws.String("X-Forwarded-For"),
						FallbackBehavior: svcsdktypes.FallbackBehaviorMatch,
					},
				},
			},
			{
				NotStatement: &svcsdktypes.NotStatement{
					Statement: &svcsdktypes.Statement{
						ByteMatchStatement: &svcsdktypes.ByteMatchStatement{
							FieldToMatch: &svcsdktypes.FieldToMatch{
								SingleHeader: &svcsdktypes.SingleHeader{
									Name: aws.String("Referer"),
								},
							},
							PositionalConstraint: svcsdktypes.PositionalConstraintExactly,
							SearchString:         []byte("something"),
							TextTransformations: []svcsdktypes.TextTransformation{
								{Priority: 0, Type: svcsdktypes.TextTransformationTypeNone},
							},
						},
					},
				},
			},
		},
	}
}

// observedStatementString reproduces what setOutputRulesNestedStatements writes
// into the CRD string field after GetWebACL returns the rule tree.
func observedStatementString(t *testing.T, stmt *svcsdktypes.AndStatement) *string {
	t.Helper()
	s, err := statementToString(stmt)
	if err != nil {
		t.Fatalf("statementToString: %v", err)
	}
	return s
}

func webACLWithStatement(stmt *svcapitypes.Statement) *resource {
	return &resource{
		ko: &svcapitypes.WebACL{
			Spec: svcapitypes.WebACLSpec{
				Name:  aws.String("test-acl"),
				Scope: aws.String("REGIONAL"),
				DefaultAction: &svcapitypes.DefaultAction{
					Allow: &svcapitypes.AllowAction{},
				},
				VisibilityConfig: &svcapitypes.VisibilityConfig{
					MetricName:               aws.String("test-metric"),
					SampledRequestsEnabled:   aws.Bool(false),
					CloudWatchMetricsEnabled: aws.Bool(false),
				},
				Rules: []*svcapitypes.Rule{
					{
						Name:     aws.String("rule-1"),
						Priority: aws.Int64(1),
						Action: &svcapitypes.RuleAction{
							Block: &svcapitypes.BlockAction{},
						},
						VisibilityConfig: &svcapitypes.VisibilityConfig{
							MetricName:               aws.String("rule-1-metric"),
							SampledRequestsEnabled:   aws.Bool(false),
							CloudWatchMetricsEnabled: aws.Bool(false),
						},
						Statement: stmt,
					},
				},
			},
		},
	}
}

func TestNewResourceDelta_NestedAndStatement_AuthoredMatchesAWSReturned(t *testing.T) {
	desired := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: aws.String(authoredAndStatement),
	})
	latest := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: observedStatementString(t, sdkAndStatement("US", "CA")),
	})

	if equality.Semantic.Equalities.DeepEqual(desired.ko.Spec.Rules, latest.ko.Spec.Rules) {
		t.Fatalf("test is vacuous: the two serializations are already byte-equal")
	}

	delta := newResourceDelta(desired, latest)
	if delta.DifferentAt("Spec.Rules") {
		t.Fatalf("expected no Spec.Rules delta, got:\nA: %s\nB: %s",
			*desired.ko.Spec.Rules[0].Statement.AndStatement,
			*latest.ko.Spec.Rules[0].Statement.AndStatement)
	}
}

func TestNewResourceDelta_NestedAndStatement_GenuineChangeDetected(t *testing.T) {
	desired := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: aws.String(authoredAndStatement),
	})
	latest := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: observedStatementString(t, sdkAndStatement("US", "GB")),
	})

	delta := newResourceDelta(desired, latest)
	if !delta.DifferentAt("Spec.Rules") {
		t.Fatal("expected a Spec.Rules delta when the country codes differ")
	}
}

func TestNewResourceDelta_NestedOrStatement_AuthoredMatchesAWSReturned(t *testing.T) {
	authored := `statements:
  - geoMatchStatement:
      countryCodes: [US]
  - ipSetReferenceStatement:
      arn: arn:aws:wafv2:us-west-2:111122223333:regional/ipset/my-set/abc-123
`
	observed, err := statementToString(&svcsdktypes.OrStatement{
		Statements: []svcsdktypes.Statement{
			{GeoMatchStatement: &svcsdktypes.GeoMatchStatement{CountryCodes: []svcsdktypes.CountryCode{"US"}}},
			{IPSetReferenceStatement: &svcsdktypes.IPSetReferenceStatement{
				ARN: aws.String("arn:aws:wafv2:us-west-2:111122223333:regional/ipset/my-set/abc-123"),
			}},
		},
	})
	if err != nil {
		t.Fatalf("statementToString: %v", err)
	}

	desired := webACLWithStatement(&svcapitypes.Statement{OrStatement: aws.String(authored)})
	latest := webACLWithStatement(&svcapitypes.Statement{OrStatement: observed})

	delta := newResourceDelta(desired, latest)
	if delta.DifferentAt("Spec.Rules") {
		t.Fatalf("expected no Spec.Rules delta, got:\nA: %s\nB: %s", authored, *observed)
	}
}

func TestNewResourceDelta_NestedNotStatement_AuthoredMatchesAWSReturned(t *testing.T) {
	authored := `statement:
  geoMatchStatement:
    countryCodes: [CN]
`
	observed, err := statementToString(&svcsdktypes.NotStatement{
		Statement: &svcsdktypes.Statement{
			GeoMatchStatement: &svcsdktypes.GeoMatchStatement{
				CountryCodes: []svcsdktypes.CountryCode{"CN"},
			},
		},
	})
	if err != nil {
		t.Fatalf("statementToString: %v", err)
	}

	desired := webACLWithStatement(&svcapitypes.Statement{NotStatement: aws.String(authored)})
	latest := webACLWithStatement(&svcapitypes.Statement{NotStatement: observed})

	delta := newResourceDelta(desired, latest)
	if delta.DifferentAt("Spec.Rules") {
		t.Fatalf("expected no Spec.Rules delta, got:\nA: %s\nB: %s", authored, *observed)
	}
}

func TestNewResourceDelta_ScopeDownStatement_AuthoredMatchesAWSReturned(t *testing.T) {
	authored := `geoMatchStatement:
  countryCodes: [US, CA]
`
	observed, err := statementToString(&svcsdktypes.Statement{
		GeoMatchStatement: &svcsdktypes.GeoMatchStatement{
			CountryCodes: []svcsdktypes.CountryCode{"US", "CA"},
		},
	})
	if err != nil {
		t.Fatalf("statementToString: %v", err)
	}

	desired := webACLWithStatement(&svcapitypes.Statement{
		RateBasedStatement: &svcapitypes.RateBasedStatement{
			AggregateKeyType:   aws.String("IP"),
			Limit:              aws.Int64(2000),
			ScopeDownStatement: aws.String(authored),
		},
		ManagedRuleGroupStatement: &svcapitypes.ManagedRuleGroupStatement{
			Name:               aws.String("AWSManagedRulesCommonRuleSet"),
			VendorName:         aws.String("AWS"),
			ScopeDownStatement: aws.String(authored),
		},
	})
	latest := webACLWithStatement(&svcapitypes.Statement{
		RateBasedStatement: &svcapitypes.RateBasedStatement{
			AggregateKeyType:   aws.String("IP"),
			Limit:              aws.Int64(2000),
			ScopeDownStatement: observed,
		},
		ManagedRuleGroupStatement: &svcapitypes.ManagedRuleGroupStatement{
			Name:               aws.String("AWSManagedRulesCommonRuleSet"),
			VendorName:         aws.String("AWS"),
			ScopeDownStatement: observed,
		},
	})

	delta := newResourceDelta(desired, latest)
	if delta.DifferentAt("Spec.Rules") {
		t.Fatalf("expected no Spec.Rules delta, got:\nA: %s\nB: %s", authored, *observed)
	}
}

func TestNewResourceDelta_UnparseableNestedStatement_FallsBackToStringCompare(t *testing.T) {
	broken := "statements: [ this is not valid yaml"

	same := newResourceDelta(
		webACLWithStatement(&svcapitypes.Statement{AndStatement: aws.String(broken)}),
		webACLWithStatement(&svcapitypes.Statement{AndStatement: aws.String(broken)}),
	)
	if same.DifferentAt("Spec.Rules") {
		t.Fatal("expected no Spec.Rules delta for identical unparseable statements")
	}

	different := newResourceDelta(
		webACLWithStatement(&svcapitypes.Statement{AndStatement: aws.String(broken)}),
		webACLWithStatement(&svcapitypes.Statement{AndStatement: aws.String(broken + " more")}),
	)
	if !different.DifferentAt("Spec.Rules") {
		t.Fatal("expected a Spec.Rules delta for differing unparseable statements")
	}
}

func TestNewResourceDelta_NestedStatementComparisonDoesNotMutateInputs(t *testing.T) {
	desired := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: aws.String(authoredAndStatement),
	})
	latest := webACLWithStatement(&svcapitypes.Statement{
		AndStatement: observedStatementString(t, sdkAndStatement("US", "CA")),
	})

	desiredBefore := desired.ko.DeepCopy()
	latestBefore := latest.ko.DeepCopy()

	_ = newResourceDelta(desired, latest)

	if !equality.Semantic.Equalities.DeepEqual(desiredBefore, desired.ko) {
		t.Fatalf("desired was mutated by newResourceDelta: now %s",
			*desired.ko.Spec.Rules[0].Statement.AndStatement)
	}
	if !equality.Semantic.Equalities.DeepEqual(latestBefore, latest.ko) {
		t.Fatalf("latest was mutated by newResourceDelta: now %s",
			*latest.ko.Spec.Rules[0].Statement.AndStatement)
	}
}

func TestNewResourceDelta_NoRules_IsSafe(t *testing.T) {
	a := webACLWithStatement(nil)
	a.ko.Spec.Rules = nil
	b := webACLWithStatement(nil)
	b.ko.Spec.Rules = nil

	if newResourceDelta(a, b).DifferentAt("Spec.Rules") {
		t.Fatal("expected no Spec.Rules delta when neither resource has rules")
	}

	withNilStatement := webACLWithStatement(nil)
	if newResourceDelta(withNilStatement, webACLWithStatement(nil)).DifferentAt("Spec.Rules") {
		t.Fatal("expected no Spec.Rules delta when the rule has no statement")
	}
}
