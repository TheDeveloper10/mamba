package mamba

import "time"

// the only reason for these to exist is testing
var (
	newTokenNow    = time.Now
	decodeTokenNow = time.Now
)
