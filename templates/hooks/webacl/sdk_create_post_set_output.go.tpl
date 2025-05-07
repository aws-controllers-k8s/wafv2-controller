	// After creation, sync the logging configuration if specified
	if ko.Spec.LoggingConfiguration != nil {
		if err = syncLoggingConfiguration(ctx, rm, &resource{ko}, nil); err != nil {
			return nil, err
		}
	}
	