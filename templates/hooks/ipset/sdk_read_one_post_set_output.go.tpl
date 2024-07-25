	if resp.IPSet != nil {
		if resp.IPSet.Description != nil {
			ko.Spec.Description = resp.IPSet.Description
		}
		if resp.IPSet.Addresses != nil {
			ko.Spec.Addresses = resp.IPSet.Addresses
		}
	}