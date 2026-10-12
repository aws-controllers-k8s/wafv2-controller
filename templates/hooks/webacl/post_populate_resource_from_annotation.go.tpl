	if _, ok := fields["id"]; !ok {
		return ackerrors.NewTerminalError(fmt.Errorf("required field missing: id"))
	}
	if _, ok := fields["scope"]; !ok {
		return ackerrors.NewTerminalError(fmt.Errorf("required field missing: scope"))
	}
