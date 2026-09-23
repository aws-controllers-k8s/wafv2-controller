	if err := rm.setInputRulesNestedStatements(input.Rules, desired); err != nil {
		return nil, err
	}

	// Use optimistic lock token from latest to ensure token is not stale due to 
	// out of band update or failed write to k8s api server.
	if latest.ko.Status.LockToken != nil {
		input.LockToken = latest.ko.Status.LockToken
	}


	// Carry the latest observed status onto a copy of desired so the returned
	// resource reflects the observed state (including conditions) rather than a
	// stale create-time condition, allowing the resource to converge to synced.
	updatedDesired := rm.concreteResource(desired.DeepCopy())
	updatedDesired.SetStatus(latest)
	if delta.DifferentAt("Spec.LoggingConfiguration") {
		// Call the syncLoggingConfiguration function to update the logging configuration
		err = syncLoggingConfiguration(ctx, rm, updatedDesired, delta)
		if err != nil {
			return nil, err
		}
	}
    if !delta.DifferentExcept("Spec.LoggingConfiguration") {
        return rm.concreteResource(updatedDesired), nil
    }
