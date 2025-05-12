	if err := rm.setInputRulesNestedStatements(input.Rules, desired); err != nil {
		return nil, err
	}
	if delta.DifferentAt("Spec.LoggingConfiguration") {
		// Call the syncLoggingConfiguration function to update the logging configuration
		err = syncLoggingConfiguration(ctx, rm, desired, delta)
		if err != nil {
			return nil, err
		}
	}
    if !delta.DifferentExcept("Spec.LoggingConfiguration") {
        return
    }