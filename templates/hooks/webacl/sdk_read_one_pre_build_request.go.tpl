    // neither ID nor ARN are individually required fields in the API, however,
    // specifying none of them results in a 400 Bad Request error.
	if r.ko.Status.ID == nil && 
	(r.ko.Status.ACKResourceMetadata == nil || r.ko.Status.ACKResourceMetadata.ARN == nil) {
		return nil, ackerr.NotFound	
	}