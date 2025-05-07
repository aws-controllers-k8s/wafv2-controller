 	if err := rm.setResourceAdditionalFields(ctx, ko, resp); err != nil {
		return &resource{ko}, err
	}
