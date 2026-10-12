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

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"

	svcapitypes "github.com/aws-controllers-k8s/wafv2-controller/apis/v1alpha1"
)

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

func TestCustomCheckRequiredFieldsMissing(t *testing.T) {
	arn := ackv1alpha1.AWSResourceName("arn:aws:wafv2:us-west-2:111122223333:regional/webacl/my-acl/abc-123")

	cases := []struct {
		name        string
		webACLName  *string
		scope       *string
		id          *string
		arn         *ackv1alpha1.AWSResourceName
		wantMissing bool
	}{
		{
			name:        "name, scope and id are sufficient",
			webACLName:  aws.String("my-acl"),
			scope:       aws.String("REGIONAL"),
			id:          aws.String("abc-123"),
			wantMissing: false,
		},
		{
			name:        "arn without id is missing",
			webACLName:  aws.String("my-acl"),
			scope:       aws.String("REGIONAL"),
			arn:         &arn,
			wantMissing: true,
		},
		{
			name:        "missing id",
			webACLName:  aws.String("my-acl"),
			scope:       aws.String("REGIONAL"),
			wantMissing: true,
		},
		{
			name:        "missing scope",
			webACLName:  aws.String("my-acl"),
			id:          aws.String("abc-123"),
			wantMissing: true,
		},
		{
			name:        "missing name",
			scope:       aws.String("REGIONAL"),
			id:          aws.String("abc-123"),
			wantMissing: true,
		},
	}

	rm := &resourceManager{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ko := &svcapitypes.WebACL{}
			ko.Spec.Name = tc.webACLName
			ko.Spec.Scope = tc.scope
			ko.Status.ID = tc.id
			if tc.arn != nil {
				ko.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: tc.arn}
			}
			if got := rm.customCheckRequiredFieldsMissing(&resource{ko: ko}); got != tc.wantMissing {
				t.Fatalf("expected %v, got %v", tc.wantMissing, got)
			}
		})
	}
}

func TestPopulateResourceFromAnnotation(t *testing.T) {
	cases := []struct {
		name         string
		fields       map[string]string
		specScope    *string
		wantTerminal bool
		wantName     string
		wantScope    string
		wantID       string
	}{
		{
			name:      "name, id and scope are accepted",
			fields:    map[string]string{"name": "my-acl", "id": "abc-123", "scope": "REGIONAL"},
			wantName:  "my-acl",
			wantScope: "REGIONAL",
			wantID:    "abc-123",
		},
		{
			name:         "arn alone is a terminal error",
			fields:       map[string]string{"arn": "arn:aws:wafv2:us-west-2:111122223333:regional/webacl/my-acl/abc-123"},
			wantTerminal: true,
		},
		{
			name:         "missing id is a terminal error",
			fields:       map[string]string{"name": "my-acl", "scope": "REGIONAL"},
			wantTerminal: true,
		},
		{
			name:         "missing scope is a terminal error",
			fields:       map[string]string{"name": "my-acl", "id": "abc-123"},
			wantTerminal: true,
		},
		{
			name:         "scope set on the spec but missing from fields is a terminal error",
			fields:       map[string]string{"name": "my-acl", "id": "abc-123"},
			specScope:    aws.String("REGIONAL"),
			wantTerminal: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &resource{ko: &svcapitypes.WebACL{}}
			r.ko.Spec.Scope = tc.specScope
			err := r.PopulateResourceFromAnnotation(tc.fields)
			if tc.wantTerminal {
				var termErr *ackerr.TerminalError
				if !errors.As(err, &termErr) {
					t.Fatalf("expected a terminal error, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got := aws.ToString(r.ko.Spec.Name); got != tc.wantName {
				t.Errorf("name: expected %q, got %q", tc.wantName, got)
			}
			if got := aws.ToString(r.ko.Spec.Scope); got != tc.wantScope {
				t.Errorf("scope: expected %q, got %q", tc.wantScope, got)
			}
			if got := aws.ToString(r.ko.Status.ID); got != tc.wantID {
				t.Errorf("id: expected %q, got %q", tc.wantID, got)
			}
		})
	}
}
