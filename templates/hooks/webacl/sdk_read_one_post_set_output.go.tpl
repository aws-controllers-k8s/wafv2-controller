	if resp.LockToken != nil {
		ko.Status.LockToken = resp.LockToken
	}
	for i, rule := range resp.WebACL.Rules {
		if rule.Statement != nil {				
			if rule.Statement.AndStatement != nil {
				ko.Spec.Rules[i].Statement.AndStatement, err = statementToString(rule.Statement.AndStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.OrStatement != nil {
				ko.Spec.Rules[i].Statement.OrStatement, err = statementToString(rule.Statement.OrStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.NotStatement != nil {
				ko.Spec.Rules[i].Statement.NotStatement, err = statementToString(rule.Statement.NotStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
				ko.Spec.Rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = statementToString(rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
				ko.Spec.Rules[i].Statement.RateBasedStatement.ScopeDownStatement, err = statementToString(rule.Statement.RateBasedStatement.ScopeDownStatement)
				if err != nil {
					return nil, err
				}
			}
		}
	}