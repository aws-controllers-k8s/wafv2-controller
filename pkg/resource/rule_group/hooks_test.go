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

package rule_group

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
)

// ruleGroupWithAndStatement builds a RuleGroup carrying a single rule whose
// statement is the supplied serialized AndStatement.
func ruleGroupWithAndStatement(andStatement *string) *resource {
	return &resource{ko: &svcapitypes.RuleGroup{
		Spec: svcapitypes.RuleGroupSpec{
			Name: aws.String("my-rule-group"),
			Rules: []*svcapitypes.Rule{
				{
					Name:     aws.String("rule-1"),
					Priority: aws.Int64(1),
					Statement: &svcapitypes.Statement{
						AndStatement: andStatement,
					},
				},
			},
		},
	}}
}

// sdkRenderedAndStatement returns the AndStatement rendering the ReadOne path
// writes back into the spec, for the supplied country codes.
func sdkRenderedAndStatement(t *testing.T, codes ...string) *string {
	t.Helper()
	countryCodes := make([]svcsdktypes.CountryCode, 0, len(codes))
	for _, c := range codes {
		countryCodes = append(countryCodes, svcsdktypes.CountryCode(c))
	}
	rendered, err := statementToString(&svcsdktypes.AndStatement{
		Statements: []svcsdktypes.Statement{
			{
				GeoMatchStatement: &svcsdktypes.GeoMatchStatement{
					CountryCodes: countryCodes,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("rendering AndStatement: %v", err)
	}
	return rendered
}

const authoredAndStatement = `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
`

func TestNewResourceDeltaNestedStatements(t *testing.T) {
	t.Run("authored and observed renderings of the same statement match", func(t *testing.T) {
		desired := ruleGroupWithAndStatement(aws.String(authoredAndStatement))
		latest := ruleGroupWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))

		delta := newResourceDelta(desired, latest)

		if delta.DifferentAt("Spec.Rules") {
			t.Errorf("expected no Spec.Rules delta, got %v", delta.Differences)
		}
	})

	t.Run("a genuinely different statement is still detected", func(t *testing.T) {
		desired := ruleGroupWithAndStatement(aws.String(authoredAndStatement))
		latest := ruleGroupWithAndStatement(sdkRenderedAndStatement(t, "US", "MX"))

		delta := newResourceDelta(desired, latest)

		if !delta.DifferentAt("Spec.Rules") {
			t.Error("expected a Spec.Rules delta for differing country codes")
		}
	})

	t.Run("comparison does not mutate its inputs", func(t *testing.T) {
		desired := ruleGroupWithAndStatement(aws.String(authoredAndStatement))
		latest := ruleGroupWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))
		desiredBefore := *desired.ko.Spec.Rules[0].Statement.AndStatement

		newResourceDelta(desired, latest)

		if got := *desired.ko.Spec.Rules[0].Statement.AndStatement; got != desiredBefore {
			t.Errorf("desired was rewritten to %q", got)
		}
	})
}
