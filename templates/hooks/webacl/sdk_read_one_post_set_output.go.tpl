	if resp.LockToken != nil {
 		ko.Status.LockToken = resp.LockToken
 	}
	if err := rm.setOutputRulesNestedStatements(ko.Spec.Rules, resp); err != nil {
		return nil, err
	}
    