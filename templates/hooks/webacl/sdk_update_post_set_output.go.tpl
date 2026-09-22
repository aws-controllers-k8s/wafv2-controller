	// UpdateWebACL rotates the optimistic-locking token, so publish the token it
	// returned rather than the one read before the call. Carry the observed status
	// across too, so the resource converges instead of requeueing to re-read.
	ko.Status = *updatedDesired.ko.Status.DeepCopy()
	if resp.NextLockToken != nil {
		ko.Status.LockToken = resp.NextLockToken
	}
