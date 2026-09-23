	// Re-read status fields for resource to ensure that values impacted by the update
	// reflect the change (see https://github.com/aws-controllers-k8s/community/issues/2852)
	refreshed, err := rm.sdkFind(ctx, latest)
	if err != nil {
		return nil, err
	}
	synced := rm.concreteResource(desired.DeepCopy())
	synced.SetStatus(refreshed)
	return synced, nil
