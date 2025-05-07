package web_acl

import (
	"context"
	"errors"

	"github.com/ghodss/yaml"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
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

	sdkLoggingConfig := &svcsdktypes.LoggingConfiguration{
		ResourceArn: aws.String(string(*ko.Status.ACKResourceMetadata.ARN)),
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
				// WAFNonexistentItemException is not a fatal error for a read operation.
				// It implies that Logging has not been enabled using the PutLoggingConfiguration call.
				// We log it and proceed, loggingConfigResp will be nil in this case.
				rlog.Info("Logging has not been enabled for the WebACL", "WebACL", *ko.Status.ACKResourceMetadata.ARN)
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
