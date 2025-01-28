func (rm *resourceManager) setOutputRulesNestedStatements (
	outputRules []*svcapitypes.Rule,
	sdkFindOutput *svcsdk.Get{{ .CRD.Names.Camel }}Output,
) (err error) {
	for i, rule := range sdkFindOutput.{{ .CRD.Names.Camel }}.Rules {
		if rule.Statement != nil {				
			if rule.Statement.AndStatement != nil {
				outputRules[i].Statement.AndStatement, err = statementToString(rule.Statement.AndStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.OrStatement != nil {
				outputRules[i].Statement.OrStatement, err = statementToString(rule.Statement.OrStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.NotStatement != nil {
				outputRules[i].Statement.NotStatement, err = statementToString(rule.Statement.NotStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
				outputRules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = statementToString(rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
				outputRules[i].Statement.RateBasedStatement.ScopeDownStatement, err = statementToString(rule.Statement.RateBasedStatement.ScopeDownStatement)
				if err != nil {
					return err
				}
			}
		}
	}
	return err
}

func (rm *resourceManager) setInputRulesNestedStatements (
    inputRules []svcsdktypes.Rule,
	r *resource,
) (err error) {
	for i, rule := range r.ko.Spec.Rules {
		if rule.Statement != nil {				
			if rule.Statement.AndStatement != nil {
				inputRules[i].Statement.AndStatement, err = stringToStatement[svcsdktypes.AndStatement](rule.Statement.AndStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.OrStatement != nil {
				inputRules[i].Statement.OrStatement, err = stringToStatement[svcsdktypes.OrStatement](rule.Statement.OrStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.NotStatement != nil {
				inputRules[i].Statement.NotStatement, err = stringToStatement[svcsdktypes.NotStatement](rule.Statement.NotStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.ManagedRuleGroupStatement != nil && rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement != nil {
				inputRules[i].Statement.ManagedRuleGroupStatement.ScopeDownStatement, err = stringToStatement[svcsdktypes.Statement](rule.Statement.ManagedRuleGroupStatement.ScopeDownStatement)
				if err != nil {
					return err
				}
			}
			if rule.Statement.RateBasedStatement != nil && rule.Statement.RateBasedStatement.ScopeDownStatement != nil {
				inputRules[i].Statement.RateBasedStatement.ScopeDownStatement, err = stringToStatement[svcsdktypes.Statement](rule.Statement.RateBasedStatement.ScopeDownStatement)
				if err != nil {
					return err
				}
			}
		}
	}
    return err
}
