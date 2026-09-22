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

// fixtureAndStatement renders the e2e fixture's AndStatement as GetWebACL
// returns it, with the byte-match header name supplied by the caller so a test
// can model WAF's server-side lowercasing.
func fixtureAndStatement(t *testing.T, headerName string) *string {
	t.Helper()
	rendered, err := statementToString(&svcsdktypes.AndStatement{
		Statements: []svcsdktypes.Statement{
			{
				GeoMatchStatement: &svcsdktypes.GeoMatchStatement{
					CountryCodes: []svcsdktypes.CountryCode{"US", "CA"},
				},
			},
			{
				NotStatement: &svcsdktypes.NotStatement{
					Statement: &svcsdktypes.Statement{
						ByteMatchStatement: &svcsdktypes.ByteMatchStatement{
							FieldToMatch: &svcsdktypes.FieldToMatch{
								SingleHeader: &svcsdktypes.SingleHeader{
									Name: aws.String(headerName),
								},
							},
							PositionalConstraint: svcsdktypes.PositionalConstraintExactly,
							SearchString:         []byte("something"),
							TextTransformations: []svcsdktypes.TextTransformation{
								{Type: svcsdktypes.TextTransformationTypeNone, Priority: 0},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("rendering fixture AndStatement: %v", err)
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

	t.Run("an unknown nested key stays a visible delta", func(t *testing.T) {
		// Identical to the authored statement except for a key the SDK does not
		// define. Dropping it silently would make this compare equal to the
		// observed form, so the resource would report Synced while the requested
		// change was never applied.
		withUnknownKey := `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
      notARealField: oops
`
		desired := ruleGroupWithAndStatement(aws.String(withUnknownKey))
		latest := ruleGroupWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))

		delta := newResourceDelta(desired, latest)

		if !delta.DifferentAt("Spec.Rules") {
			t.Error("expected an unknown nested key to remain a visible delta")
		}
	})

	t.Run("a header name WAF lowercased server-side is not a delta", func(t *testing.T) {
		// The repository's own nested-statement fixture, whose byte-match inspects
		// singleHeader "Referer". WAF stores header names lowercased, so GetWebACL
		// returns "referer" and only a value normalisation can reconcile the two.
		authored := `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
  - notStatement:
      statement:
        byteMatchStatement:
          fieldToMatch:
            singleHeader:
              name: Referer
          positionalConstraint: EXACTLY
          searchString: c29tZXRoaW5n
          textTransformations:
            - type: NONE
              priority: 0
`
		observed := fixtureAndStatement(t, "referer")

		delta := newResourceDelta(
			ruleGroupWithAndStatement(aws.String(authored)),
			ruleGroupWithAndStatement(observed),
		)

		if delta.DifferentAt("Spec.Rules") {
			t.Errorf("expected no Spec.Rules delta for a server-lowercased header, got %v", delta.Differences)
		}
	})

	t.Run("a genuinely different header name is still a delta", func(t *testing.T) {
		authored := `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
  - notStatement:
      statement:
        byteMatchStatement:
          fieldToMatch:
            singleHeader:
              name: Referer
          positionalConstraint: EXACTLY
          searchString: c29tZXRoaW5n
          textTransformations:
            - type: NONE
              priority: 0
`
		delta := newResourceDelta(
			ruleGroupWithAndStatement(aws.String(authored)),
			ruleGroupWithAndStatement(fixtureAndStatement(t, "user-agent")),
		)

		if !delta.DifferentAt("Spec.Rules") {
			t.Error("expected a Spec.Rules delta when the header name genuinely differs")
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
