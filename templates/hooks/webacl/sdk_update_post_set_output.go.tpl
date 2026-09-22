	// UpdateWebACL rotates the resource's lock token and returns only the new
	// token, not the updated resource. Read the resource back so the returned
	// object carries the current observed status -- including the rotated lock
	// token -- and return it with no requeue. sdkUpdate previously requeued
	// after one second to force that re-read; against WAF's account-wide 1 rps
	// write quota that turned any residual delta into a per-second update loop.
	refreshed, err := rm.sdkFind(ctx, latest)
	if err != nil {
		return nil, err
	}
	synced := rm.concreteResource(desired.DeepCopy())
	synced.SetStatus(refreshed)
	return synced, nil
