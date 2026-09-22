package web_acl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ghodss/yaml"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"k8s.io/apimachinery/pkg/api/equality"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/wafv2"

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

// setLoggingConfiguration populates the WebACL's logging configuration
func setLoggingConfiguration(
	ko *svcapitypes.WebACL,
	loggingConfig *svcsdktypes.LoggingConfiguration,
) {
	if ko.Spec.LoggingConfiguration == nil {
		ko.Spec.LoggingConfiguration = &svcapitypes.LoggingConfiguration{}
	}

	if loggingConfig.LogDestinationConfigs != nil {
		ko.Spec.LoggingConfiguration.LogDestinationConfigs = aws.StringSlice(loggingConfig.LogDestinationConfigs)
	}

	if loggingConfig.ResourceArn != nil {
		ko.Spec.LoggingConfiguration.ResourceARN = loggingConfig.ResourceArn
	}

	if loggingConfig.LogScope != "" {
		ko.Spec.LoggingConfiguration.LogScope = aws.String(string(loggingConfig.LogScope))
	}

	if loggingConfig.LogType != "" {
		ko.Spec.LoggingConfiguration.LogType = aws.String(string(loggingConfig.LogType))
	}

	ko.Spec.LoggingConfiguration.ManagedByFirewallManager = aws.Bool(loggingConfig.ManagedByFirewallManager)

	if loggingConfig.LoggingFilter != nil {
		filter := &svcapitypes.LoggingFilter{}

		if loggingConfig.LoggingFilter.DefaultBehavior != "" {
			filter.DefaultBehavior = aws.String(string(loggingConfig.LoggingFilter.DefaultBehavior))
		}

		if loggingConfig.LoggingFilter.Filters != nil {
			var filters []*svcapitypes.Filter

			for _, f := range loggingConfig.LoggingFilter.Filters {
				filter := &svcapitypes.Filter{}

				if f.Behavior != "" {
					filter.Behavior = aws.String(string(f.Behavior))
				}

				if f.Requirement != "" {
					filter.Requirement = aws.String(string(f.Requirement))
				}

				if f.Conditions != nil {
					var conditions []*svcapitypes.Condition

					for _, c := range f.Conditions {
						condition := &svcapitypes.Condition{}

						if c.ActionCondition != nil {
							actionCondition := &svcapitypes.ActionCondition{}
							if c.ActionCondition.Action != "" {
								actionCondition.Action = aws.String(string(c.ActionCondition.Action))
							}
							condition.ActionCondition = actionCondition
						}

						if c.LabelNameCondition != nil {
							labelNameCondition := &svcapitypes.LabelNameCondition{}
							if c.LabelNameCondition.LabelName != nil {
								labelNameCondition.LabelName = c.LabelNameCondition.LabelName
							}
							condition.LabelNameCondition = labelNameCondition
						}

						conditions = append(conditions, condition)
					}

					filter.Conditions = conditions
				}

				filters = append(filters, filter)
			}

			filter.Filters = filters
		}

		ko.Spec.LoggingConfiguration.LoggingFilter = filter
	}

	if loggingConfig.RedactedFields != nil {
		var redactedFields []*svcapitypes.FieldToMatch

		for _, field := range loggingConfig.RedactedFields {
			redactedField := &svcapitypes.FieldToMatch{}

			if field.AllQueryArguments != nil {
				redactedField.AllQueryArguments = map[string]*string{}
			}

			if field.Body != nil {
				body := &svcapitypes.Body{}
				if field.Body.OversizeHandling != "" {
					body.OversizeHandling = aws.String(string(field.Body.OversizeHandling))
				}
				redactedField.Body = body
			}

			if field.Method != nil {
				redactedField.Method = map[string]*string{}
			}

			if field.QueryString != nil {
				redactedField.QueryString = map[string]*string{}
			}

			if field.SingleHeader != nil {
				singleHeader := &svcapitypes.SingleHeader{}
				if field.SingleHeader.Name != nil {
					singleHeader.Name = field.SingleHeader.Name
				}
				redactedField.SingleHeader = singleHeader
			}

			if field.UriPath != nil {
				redactedField.URIPath = map[string]*string{}
			}

			redactedFields = append(redactedFields, redactedField)
		}

		ko.Spec.LoggingConfiguration.RedactedFields = redactedFields
	}
}

// validateLoggingResourceARN ensures a user-supplied ResourceARN is either unset
// or the WebACL's own ARN, returning a terminal error otherwise.
func validateLoggingResourceARN(resourceARN *string, webACLARN string) error {
	if resourceARN != nil && *resourceARN != webACLARN {
		return ackerr.NewTerminalError(fmt.Errorf(
			"invalid spec.loggingConfiguration.resourceARN %q: must be unset or the WebACL's own ARN %q",
			*resourceARN, webACLARN))
	}
	return nil
}

// syncLoggingConfiguration syncs the WebACL's logging configuration by sending a PutLoggingConfiguration request
func syncLoggingConfiguration(
	ctx context.Context,
	rm *resourceManager,
	desired *resource,
	delta *ackcompare.Delta,
) error {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("syncLoggingConfiguration")
	defer func() {
		exit(nil)
	}()

	ko := desired.ko
	if ko.Spec.LoggingConfiguration == nil {
		return nil
	}

	// Check if we have the ARN available - it might not be during creation
	if ko.Status.ACKResourceMetadata == nil || ko.Status.ACKResourceMetadata.ARN == nil {
		return nil
	}

	webACLARN := string(*ko.Status.ACKResourceMetadata.ARN)

	if err := validateLoggingResourceARN(ko.Spec.LoggingConfiguration.ResourceARN, webACLARN); err != nil {
		return err
	}

	sdkLoggingConfig := &svcsdktypes.LoggingConfiguration{
		ResourceArn: aws.String(webACLARN),
	}

	if ko.Spec.LoggingConfiguration.LogDestinationConfigs != nil {
		sdkLoggingConfig.LogDestinationConfigs = aws.ToStringSlice(ko.Spec.LoggingConfiguration.LogDestinationConfigs)
	}

	if ko.Spec.LoggingConfiguration.LogScope != nil {
		sdkLoggingConfig.LogScope = svcsdktypes.LogScope(*ko.Spec.LoggingConfiguration.LogScope)
	}

	if ko.Spec.LoggingConfiguration.LogType != nil {
		sdkLoggingConfig.LogType = svcsdktypes.LogType(*ko.Spec.LoggingConfiguration.LogType)
	}

	if ko.Spec.LoggingConfiguration.ManagedByFirewallManager != nil {
		sdkLoggingConfig.ManagedByFirewallManager = *ko.Spec.LoggingConfiguration.ManagedByFirewallManager
	}

	if ko.Spec.LoggingConfiguration.LoggingFilter != nil {
		filter := &svcsdktypes.LoggingFilter{}

		if ko.Spec.LoggingConfiguration.LoggingFilter.DefaultBehavior != nil {
			filter.DefaultBehavior = svcsdktypes.FilterBehavior(*ko.Spec.LoggingConfiguration.LoggingFilter.DefaultBehavior)
		}

		if ko.Spec.LoggingConfiguration.LoggingFilter.Filters != nil {
			var filters []svcsdktypes.Filter

			for _, f := range ko.Spec.LoggingConfiguration.LoggingFilter.Filters {
				filter := svcsdktypes.Filter{}

				if f.Behavior != nil {
					filter.Behavior = svcsdktypes.FilterBehavior(*f.Behavior)
				}

				if f.Requirement != nil {
					filter.Requirement = svcsdktypes.FilterRequirement(*f.Requirement)
				}

				if f.Conditions != nil {
					var conditions []svcsdktypes.Condition

					for _, c := range f.Conditions {
						condition := svcsdktypes.Condition{}

						if c.ActionCondition != nil && c.ActionCondition.Action != nil {
							condition.ActionCondition = &svcsdktypes.ActionCondition{
								Action: svcsdktypes.ActionValue(*c.ActionCondition.Action),
							}
						}

						if c.LabelNameCondition != nil && c.LabelNameCondition.LabelName != nil {
							condition.LabelNameCondition = &svcsdktypes.LabelNameCondition{
								LabelName: c.LabelNameCondition.LabelName,
							}
						}

						conditions = append(conditions, condition)
					}

					filter.Conditions = conditions
				}

				filters = append(filters, filter)
			}

			filter.Filters = filters
		}

		sdkLoggingConfig.LoggingFilter = filter
	}

	if ko.Spec.LoggingConfiguration.RedactedFields != nil {
		var redactedFields []svcsdktypes.FieldToMatch

		for _, field := range ko.Spec.LoggingConfiguration.RedactedFields {
			redactedField := svcsdktypes.FieldToMatch{}

			if field.AllQueryArguments != nil {
				redactedField.AllQueryArguments = &svcsdktypes.AllQueryArguments{}
			}

			if field.Body != nil {
				body := &svcsdktypes.Body{}
				if field.Body.OversizeHandling != nil {
					body.OversizeHandling = svcsdktypes.OversizeHandling(*field.Body.OversizeHandling)
				}
				redactedField.Body = body
			}

			if field.Method != nil {
				redactedField.Method = &svcsdktypes.Method{}
			}

			if field.QueryString != nil {
				redactedField.QueryString = &svcsdktypes.QueryString{}
			}

			if field.SingleHeader != nil && field.SingleHeader.Name != nil {
				redactedField.SingleHeader = &svcsdktypes.SingleHeader{
					Name: field.SingleHeader.Name,
				}
			}

			if field.URIPath != nil {
				redactedField.UriPath = &svcsdktypes.UriPath{}
			}

			redactedFields = append(redactedFields, redactedField)
		}

		sdkLoggingConfig.RedactedFields = redactedFields
	}

	// Construct the input for PutLoggingConfiguration
	input := &svcsdk.PutLoggingConfigurationInput{
		LoggingConfiguration: sdkLoggingConfig,
	}

	// Call the PutLoggingConfiguration API
	resp, err := rm.sdkapi.PutLoggingConfiguration(ctx, input)
	if err != nil {
		return err
	}

	// Update the resource with the response
	if resp.LoggingConfiguration != nil {
		setLoggingConfiguration(ko, resp.LoggingConfiguration)
	}

	return nil
}

// setResourceAdditionalFields is called after the ReadOne operation to set
// additional resource fields like LockToken, Rules and LoggingConfiguration
func (rm *resourceManager) setResourceAdditionalFields(
	ctx context.Context,
	ko *svcapitypes.WebACL,
	resp *svcsdk.GetWebACLOutput,
) error {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("setResourceAdditionalFields")
	defer func() {
		exit(nil)
	}()

	if resp.LockToken != nil {
		ko.Status.LockToken = resp.LockToken
	}
	if resp.ApplicationIntegrationURL != nil {
		ko.Status.ApplicationIntegrationURL = resp.ApplicationIntegrationURL
	}

	if err := rm.setOutputRulesNestedStatements(ko.Spec.Rules, resp); err != nil {
		return err
	}

	err := customSetOutputGetLoggingConfiguration(ctx, rm, ko)
	if err != nil {
		return err
	}

	return nil
}

// customSetOutputGetLoggingConfiguration fetches and sets the logging configuration for a WebACL.
func customSetOutputGetLoggingConfiguration(
	ctx context.Context,
	rm *resourceManager,
	ko *svcapitypes.WebACL,
) error {
	rlog := ackrtlog.FromContext(ctx)
	if ko.Status.ACKResourceMetadata != nil && ko.Status.ACKResourceMetadata.ARN != nil {
		loggingConfigInput := &svcsdk.GetLoggingConfigurationInput{
			ResourceArn: aws.String(string(*ko.Status.ACKResourceMetadata.ARN)),
		}
		loggingConfigResp, err := rm.sdkapi.GetLoggingConfiguration(ctx, loggingConfigInput)
		if err != nil {
			var nfe *svcsdktypes.WAFNonexistentItemException
			if errors.As(err, &nfe) {
				// Logging is not enabled for this WebACL in AWS. latest is
				// seeded from a copy of desired, so clear any inherited value
				// to let the delta detect a pending change and apply it.
				rlog.Info("Logging has not been enabled for the WebACL", "WebACL", *ko.Status.ACKResourceMetadata.ARN)
				ko.Spec.LoggingConfiguration = nil
			} else {
				// For any other error, it's genuinely an issue with the GetLoggingConfiguration call.
				return err
			}
		}

		if loggingConfigResp != nil && loggingConfigResp.LoggingConfiguration != nil {
			// Populate the logging configuration fields in ko.
			setLoggingConfiguration(ko, loggingConfigResp.LoggingConfiguration)
		}
	}
	return nil
}
