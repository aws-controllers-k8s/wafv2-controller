	if resp.LockToken != nil {
 		ko.Status.LockToken = resp.LockToken
 	}
	if err := rm.setOutputRulesNestedStatements(ko.Spec.Rules, resp); err != nil {
		return nil, err
	}
	
	// If we have a WebACL ARN, fetch its logging configuration
	if ko.Status.ACKResourceMetadata != nil && ko.Status.ACKResourceMetadata.ARN != nil {
		loggingConfigInput := &svcsdk.GetLoggingConfigurationInput{
			ResourceArn: aws.String(string(*ko.Status.ACKResourceMetadata.ARN)),
		}
		
		loggingConfigResp, err := rm.sdkapi.GetLoggingConfiguration(ctx, loggingConfigInput)
		if err != nil {
			return nil, err
		}
		
		if loggingConfigResp != nil && loggingConfigResp.LoggingConfiguration != nil {
			// Populate the logging configuration fields
			if err := setLoggingConfiguration(ko, loggingConfigResp.LoggingConfiguration); err != nil {
				return nil, err
			}
		}
	}
    