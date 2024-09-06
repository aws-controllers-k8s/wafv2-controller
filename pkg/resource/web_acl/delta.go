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

// Code generated by ack-generate. DO NOT EDIT.

package web_acl

import (
	"bytes"
	"reflect"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	acktags "github.com/aws-controllers-k8s/runtime/pkg/tags"
)

// Hack to avoid import errors during build...
var (
	_ = &bytes.Buffer{}
	_ = &reflect.Method{}
	_ = &acktags.Tags{}
)

// newResourceDelta returns a new `ackcompare.Delta` used to compare two
// resources
func newResourceDelta(
	a *resource,
	b *resource,
) *ackcompare.Delta {
	delta := ackcompare.NewDelta()
	if (a == nil && b != nil) ||
		(a != nil && b == nil) {
		delta.Add("", a, b)
		return delta
	}

	if ackcompare.HasNilDifference(a.ko.Spec.AssociationConfig, b.ko.Spec.AssociationConfig) {
		delta.Add("Spec.AssociationConfig", a.ko.Spec.AssociationConfig, b.ko.Spec.AssociationConfig)
	} else if a.ko.Spec.AssociationConfig != nil && b.ko.Spec.AssociationConfig != nil {
		if len(a.ko.Spec.AssociationConfig.RequestBody) != len(b.ko.Spec.AssociationConfig.RequestBody) {
			delta.Add("Spec.AssociationConfig.RequestBody", a.ko.Spec.AssociationConfig.RequestBody, b.ko.Spec.AssociationConfig.RequestBody)
		} else if len(a.ko.Spec.AssociationConfig.RequestBody) > 0 {
			if !reflect.DeepEqual(a.ko.Spec.AssociationConfig.RequestBody, b.ko.Spec.AssociationConfig.RequestBody) {
				delta.Add("Spec.AssociationConfig.RequestBody", a.ko.Spec.AssociationConfig.RequestBody, b.ko.Spec.AssociationConfig.RequestBody)
			}
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.CaptchaConfig, b.ko.Spec.CaptchaConfig) {
		delta.Add("Spec.CaptchaConfig", a.ko.Spec.CaptchaConfig, b.ko.Spec.CaptchaConfig)
	} else if a.ko.Spec.CaptchaConfig != nil && b.ko.Spec.CaptchaConfig != nil {
		if ackcompare.HasNilDifference(a.ko.Spec.CaptchaConfig.ImmunityTimeProperty, b.ko.Spec.CaptchaConfig.ImmunityTimeProperty) {
			delta.Add("Spec.CaptchaConfig.ImmunityTimeProperty", a.ko.Spec.CaptchaConfig.ImmunityTimeProperty, b.ko.Spec.CaptchaConfig.ImmunityTimeProperty)
		} else if a.ko.Spec.CaptchaConfig.ImmunityTimeProperty != nil && b.ko.Spec.CaptchaConfig.ImmunityTimeProperty != nil {
			if ackcompare.HasNilDifference(a.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime) {
				delta.Add("Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime", a.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
			} else if a.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil && b.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != nil {
				if *a.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime != *b.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime {
					delta.Add("Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime", a.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.CaptchaConfig.ImmunityTimeProperty.ImmunityTime)
				}
			}
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.ChallengeConfig, b.ko.Spec.ChallengeConfig) {
		delta.Add("Spec.ChallengeConfig", a.ko.Spec.ChallengeConfig, b.ko.Spec.ChallengeConfig)
	} else if a.ko.Spec.ChallengeConfig != nil && b.ko.Spec.ChallengeConfig != nil {
		if ackcompare.HasNilDifference(a.ko.Spec.ChallengeConfig.ImmunityTimeProperty, b.ko.Spec.ChallengeConfig.ImmunityTimeProperty) {
			delta.Add("Spec.ChallengeConfig.ImmunityTimeProperty", a.ko.Spec.ChallengeConfig.ImmunityTimeProperty, b.ko.Spec.ChallengeConfig.ImmunityTimeProperty)
		} else if a.ko.Spec.ChallengeConfig.ImmunityTimeProperty != nil && b.ko.Spec.ChallengeConfig.ImmunityTimeProperty != nil {
			if ackcompare.HasNilDifference(a.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime) {
				delta.Add("Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime", a.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
			} else if a.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil && b.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != nil {
				if *a.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime != *b.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime {
					delta.Add("Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime", a.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime, b.ko.Spec.ChallengeConfig.ImmunityTimeProperty.ImmunityTime)
				}
			}
		}
	}
	if len(a.ko.Spec.CustomResponseBodies) != len(b.ko.Spec.CustomResponseBodies) {
		delta.Add("Spec.CustomResponseBodies", a.ko.Spec.CustomResponseBodies, b.ko.Spec.CustomResponseBodies)
	} else if len(a.ko.Spec.CustomResponseBodies) > 0 {
		if !reflect.DeepEqual(a.ko.Spec.CustomResponseBodies, b.ko.Spec.CustomResponseBodies) {
			delta.Add("Spec.CustomResponseBodies", a.ko.Spec.CustomResponseBodies, b.ko.Spec.CustomResponseBodies)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction, b.ko.Spec.DefaultAction) {
		delta.Add("Spec.DefaultAction", a.ko.Spec.DefaultAction, b.ko.Spec.DefaultAction)
	} else if a.ko.Spec.DefaultAction != nil && b.ko.Spec.DefaultAction != nil {
		if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Allow, b.ko.Spec.DefaultAction.Allow) {
			delta.Add("Spec.DefaultAction.Allow", a.ko.Spec.DefaultAction.Allow, b.ko.Spec.DefaultAction.Allow)
		} else if a.ko.Spec.DefaultAction.Allow != nil && b.ko.Spec.DefaultAction.Allow != nil {
			if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Allow.CustomRequestHandling, b.ko.Spec.DefaultAction.Allow.CustomRequestHandling) {
				delta.Add("Spec.DefaultAction.Allow.CustomRequestHandling", a.ko.Spec.DefaultAction.Allow.CustomRequestHandling, b.ko.Spec.DefaultAction.Allow.CustomRequestHandling)
			} else if a.ko.Spec.DefaultAction.Allow.CustomRequestHandling != nil && b.ko.Spec.DefaultAction.Allow.CustomRequestHandling != nil {
				if len(a.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders) != len(b.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders) {
					delta.Add("Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders", a.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders, b.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders)
				} else if len(a.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders) > 0 {
					if !reflect.DeepEqual(a.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders, b.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders) {
						delta.Add("Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders", a.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders, b.ko.Spec.DefaultAction.Allow.CustomRequestHandling.InsertHeaders)
					}
				}
			}
		}
		if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Block, b.ko.Spec.DefaultAction.Block) {
			delta.Add("Spec.DefaultAction.Block", a.ko.Spec.DefaultAction.Block, b.ko.Spec.DefaultAction.Block)
		} else if a.ko.Spec.DefaultAction.Block != nil && b.ko.Spec.DefaultAction.Block != nil {
			if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Block.CustomResponse, b.ko.Spec.DefaultAction.Block.CustomResponse) {
				delta.Add("Spec.DefaultAction.Block.CustomResponse", a.ko.Spec.DefaultAction.Block.CustomResponse, b.ko.Spec.DefaultAction.Block.CustomResponse)
			} else if a.ko.Spec.DefaultAction.Block.CustomResponse != nil && b.ko.Spec.DefaultAction.Block.CustomResponse != nil {
				if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey, b.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey) {
					delta.Add("Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey", a.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey, b.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
				} else if a.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey != nil && b.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey != nil {
					if *a.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey != *b.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey {
						delta.Add("Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey", a.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey, b.ko.Spec.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
					}
				}
				if ackcompare.HasNilDifference(a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode) {
					delta.Add("Spec.DefaultAction.Block.CustomResponse.ResponseCode", a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode)
				} else if a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode != nil && b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode != nil {
					if *a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode != *b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode {
						delta.Add("Spec.DefaultAction.Block.CustomResponse.ResponseCode", a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseCode)
					}
				}
				if len(a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders) != len(b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders) {
					delta.Add("Spec.DefaultAction.Block.CustomResponse.ResponseHeaders", a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders)
				} else if len(a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders) > 0 {
					if !reflect.DeepEqual(a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders) {
						delta.Add("Spec.DefaultAction.Block.CustomResponse.ResponseHeaders", a.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders, b.ko.Spec.DefaultAction.Block.CustomResponse.ResponseHeaders)
					}
				}
			}
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.Description, b.ko.Spec.Description) {
		delta.Add("Spec.Description", a.ko.Spec.Description, b.ko.Spec.Description)
	} else if a.ko.Spec.Description != nil && b.ko.Spec.Description != nil {
		if *a.ko.Spec.Description != *b.ko.Spec.Description {
			delta.Add("Spec.Description", a.ko.Spec.Description, b.ko.Spec.Description)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.Name, b.ko.Spec.Name) {
		delta.Add("Spec.Name", a.ko.Spec.Name, b.ko.Spec.Name)
	} else if a.ko.Spec.Name != nil && b.ko.Spec.Name != nil {
		if *a.ko.Spec.Name != *b.ko.Spec.Name {
			delta.Add("Spec.Name", a.ko.Spec.Name, b.ko.Spec.Name)
		}
	}
	if len(a.ko.Spec.Rules) != len(b.ko.Spec.Rules) {
		delta.Add("Spec.Rules", a.ko.Spec.Rules, b.ko.Spec.Rules)
	} else if len(a.ko.Spec.Rules) > 0 {
		if !reflect.DeepEqual(a.ko.Spec.Rules, b.ko.Spec.Rules) {
			delta.Add("Spec.Rules", a.ko.Spec.Rules, b.ko.Spec.Rules)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.Scope, b.ko.Spec.Scope) {
		delta.Add("Spec.Scope", a.ko.Spec.Scope, b.ko.Spec.Scope)
	} else if a.ko.Spec.Scope != nil && b.ko.Spec.Scope != nil {
		if *a.ko.Spec.Scope != *b.ko.Spec.Scope {
			delta.Add("Spec.Scope", a.ko.Spec.Scope, b.ko.Spec.Scope)
		}
	}
	if !ackcompare.MapStringStringEqual(ToACKTags(a.ko.Spec.Tags), ToACKTags(b.ko.Spec.Tags)) {
		delta.Add("Spec.Tags", a.ko.Spec.Tags, b.ko.Spec.Tags)
	}
	if len(a.ko.Spec.TokenDomains) != len(b.ko.Spec.TokenDomains) {
		delta.Add("Spec.TokenDomains", a.ko.Spec.TokenDomains, b.ko.Spec.TokenDomains)
	} else if len(a.ko.Spec.TokenDomains) > 0 {
		if !ackcompare.SliceStringPEqual(a.ko.Spec.TokenDomains, b.ko.Spec.TokenDomains) {
			delta.Add("Spec.TokenDomains", a.ko.Spec.TokenDomains, b.ko.Spec.TokenDomains)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.VisibilityConfig, b.ko.Spec.VisibilityConfig) {
		delta.Add("Spec.VisibilityConfig", a.ko.Spec.VisibilityConfig, b.ko.Spec.VisibilityConfig)
	} else if a.ko.Spec.VisibilityConfig != nil && b.ko.Spec.VisibilityConfig != nil {
		if ackcompare.HasNilDifference(a.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled, b.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled) {
			delta.Add("Spec.VisibilityConfig.CloudWatchMetricsEnabled", a.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled, b.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled)
		} else if a.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled != nil && b.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled != nil {
			if *a.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled != *b.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled {
				delta.Add("Spec.VisibilityConfig.CloudWatchMetricsEnabled", a.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled, b.ko.Spec.VisibilityConfig.CloudWatchMetricsEnabled)
			}
		}
		if ackcompare.HasNilDifference(a.ko.Spec.VisibilityConfig.MetricName, b.ko.Spec.VisibilityConfig.MetricName) {
			delta.Add("Spec.VisibilityConfig.MetricName", a.ko.Spec.VisibilityConfig.MetricName, b.ko.Spec.VisibilityConfig.MetricName)
		} else if a.ko.Spec.VisibilityConfig.MetricName != nil && b.ko.Spec.VisibilityConfig.MetricName != nil {
			if *a.ko.Spec.VisibilityConfig.MetricName != *b.ko.Spec.VisibilityConfig.MetricName {
				delta.Add("Spec.VisibilityConfig.MetricName", a.ko.Spec.VisibilityConfig.MetricName, b.ko.Spec.VisibilityConfig.MetricName)
			}
		}
		if ackcompare.HasNilDifference(a.ko.Spec.VisibilityConfig.SampledRequestsEnabled, b.ko.Spec.VisibilityConfig.SampledRequestsEnabled) {
			delta.Add("Spec.VisibilityConfig.SampledRequestsEnabled", a.ko.Spec.VisibilityConfig.SampledRequestsEnabled, b.ko.Spec.VisibilityConfig.SampledRequestsEnabled)
		} else if a.ko.Spec.VisibilityConfig.SampledRequestsEnabled != nil && b.ko.Spec.VisibilityConfig.SampledRequestsEnabled != nil {
			if *a.ko.Spec.VisibilityConfig.SampledRequestsEnabled != *b.ko.Spec.VisibilityConfig.SampledRequestsEnabled {
				delta.Add("Spec.VisibilityConfig.SampledRequestsEnabled", a.ko.Spec.VisibilityConfig.SampledRequestsEnabled, b.ko.Spec.VisibilityConfig.SampledRequestsEnabled)
			}
		}
	}

	return delta
}