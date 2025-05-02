
	// Check if LoggingConfiguration fields have changed and sync if needed
	if delta.DifferentAt("Spec.LoggingConfiguration") {
		// Call the syncLoggingConfiguration function to update the logging configuration
		err = syncLoggingConfiguration(ctx, rm, desired, latest, delta)
		if err != nil {
			return nil, err
		}
	}