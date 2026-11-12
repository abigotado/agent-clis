package secretstore

import "sync"

// modeFixer records the first Interaction mode requested and refuses any other.
type modeFixer struct {
	mu   sync.Mutex
	set  bool
	mode Interaction
}

// fix records mode if none is recorded yet and reports whether mode matches the
// recorded one.
func (f *modeFixer) fix(mode Interaction) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.set {
		f.set = true
		f.mode = mode
	}
	return f.mode == mode
}

// processMode is the one piece of package state: the interaction mode is a
// process-wide property of the platform stores, so it is fixed process-wide.
var processMode modeFixer
