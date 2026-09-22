	// UpdateWebACL returns only NextLockToken, so carry the observed status
	// forward and rotate the lock token instead of requeueing for a re-read.
	ko.Status = *updatedDesired.ko.Status.DeepCopy()
	if resp.NextLockToken != nil {
		ko.Status.LockToken = resp.NextLockToken
	}
