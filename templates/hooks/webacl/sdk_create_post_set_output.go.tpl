	rm.setStatusDefaults(ko)
	
	// After creation, sync the logging configuration if specified
	if ko.Spec.LoggingConfiguration != nil {
		if err = syncLoggingConfiguration(ctx, rm, &resource{ko}, nil, nil); err != nil {
			return nil, err
		}
	}
	
	return &resource{ko}, nil