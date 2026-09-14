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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"

	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
)

// webACLWithAndStatement builds a WebACL carrying a single rule whose statement
// is the supplied serialized AndStatement.
func webACLWithAndStatement(andStatement *string) *resource {
	return &resource{ko: &svcapitypes.WebACL{
		Spec: svcapitypes.WebACLSpec{
			Name: aws.String("my-acl"),
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

// The authored form users write, as in test/e2e/resources/web_acl_nested_statement.yaml.
const authoredAndStatement = `statements:
  - geoMatchStatement:
      countryCodes:
        - US
        - CA
`

func TestNewResourceDeltaNestedStatements(t *testing.T) {
	t.Run("authored and observed renderings of the same statement match", func(t *testing.T) {
		desired := webACLWithAndStatement(aws.String(authoredAndStatement))
		latest := webACLWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))

		delta := newResourceDelta(desired, latest)

		if delta.DifferentAt("Spec.Rules") {
			t.Errorf("expected no Spec.Rules delta, got %v", delta.Differences)
		}
	})

	t.Run("a genuinely different statement is still detected", func(t *testing.T) {
		desired := webACLWithAndStatement(aws.String(authoredAndStatement))
		latest := webACLWithAndStatement(sdkRenderedAndStatement(t, "US", "MX"))

		delta := newResourceDelta(desired, latest)

		if !delta.DifferentAt("Spec.Rules") {
			t.Error("expected a Spec.Rules delta for differing country codes")
		}
	})

	t.Run("unparseable statements fall back to string comparison", func(t *testing.T) {
		garbage := aws.String("not a statement")

		if delta := newResourceDelta(
			webACLWithAndStatement(garbage),
			webACLWithAndStatement(garbage),
		); delta.DifferentAt("Spec.Rules") {
			t.Error("expected identical unparseable statements to compare equal")
		}

		if delta := newResourceDelta(
			webACLWithAndStatement(garbage),
			webACLWithAndStatement(aws.String("also not a statement")),
		); !delta.DifferentAt("Spec.Rules") {
			t.Error("expected differing unparseable statements to compare unequal")
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
		desired := webACLWithAndStatement(aws.String(withUnknownKey))
		latest := webACLWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))

		delta := newResourceDelta(desired, latest)

		if !delta.DifferentAt("Spec.Rules") {
			t.Error("expected an unknown nested key to remain a visible delta")
		}
	})

	t.Run("comparison does not mutate its inputs", func(t *testing.T) {
		desired := webACLWithAndStatement(aws.String(authoredAndStatement))
		latest := webACLWithAndStatement(sdkRenderedAndStatement(t, "US", "CA"))
		desiredBefore := *desired.ko.Spec.Rules[0].Statement.AndStatement
		latestBefore := *latest.ko.Spec.Rules[0].Statement.AndStatement

		newResourceDelta(desired, latest)

		if got := *desired.ko.Spec.Rules[0].Statement.AndStatement; got != desiredBefore {
			t.Errorf("desired was rewritten to %q", got)
		}
		if got := *latest.ko.Spec.Rules[0].Statement.AndStatement; got != latestBefore {
			t.Errorf("latest was rewritten to %q", got)
		}
	})
}

func TestValidateLoggingResourceARN(t *testing.T) {
	const webACLARN = "arn:aws:wafv2:us-west-2:111122223333:regional/webacl/my-acl/abc-123"

	cases := []struct {
		name         string
		resourceARN  *string
		wantErr      bool
		wantTerminal bool
	}{
		{
			name:        "nil is allowed",
			resourceARN: nil,
			wantErr:     false,
		},
		{
			name:        "matching own ARN is allowed",
			resourceARN: aws.String(webACLARN),
			wantErr:     false,
		},
		{
			name:         "different ARN is a terminal error",
			resourceARN:  aws.String("arn:aws:wafv2:us-west-2:111122223333:regional/webacl/other-acl/xyz-789"),
			wantErr:      true,
			wantTerminal: true,
		},
		{
			name:         "empty string is a terminal error",
			resourceARN:  aws.String(""),
			wantErr:      true,
			wantTerminal: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLoggingResourceARN(tc.resourceARN, webACLARN)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantTerminal {
				var termErr *ackerr.TerminalError
				if !errors.As(err, &termErr) {
					t.Fatalf("expected a terminal error, got %T: %v", err, err)
				}
			}
		})
	}
}
