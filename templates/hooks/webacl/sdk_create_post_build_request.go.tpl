	for i, rule := range desired.ko.Spec.Rules {
		if rule.Statement != nil {				
			if rule.Statement.AndStatement != nil {
				input.Rules[i].Statement.AndStatement, err = stringToStatement[svcsdk.AndStatement](rule.Statement.AndStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.OrStatement != nil {
				input.Rules[i].Statement.OrStatement, err = stringToStatement[svcsdk.OrStatement](rule.Statement.OrStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.NotStatement != nil {
				input.Rules[i].Statement.NotStatement, err = stringToStatement[svcsdk.NotStatement](rule.Statement.NotStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
				input.Rules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = stringToStatement[svcsdk.Statement](rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
				if err != nil {
					return nil, err
				}
			}
			if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
				input.Rules[i].Statement.RateBasedStatement.ScopeDownStatement, err = stringToStatement[svcsdk.Statement](rule.Statement.RateBasedStatement.ScopeDownStatement)
				if err != nil {
					return nil, err
				}
			}
		}
	}