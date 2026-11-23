package app

import "github.com/abigotado/agent-clis/tools/sign-release/internal/lock"

// HomeSeams are the Deps members that derive from the account's home directory:
// the home itself, the whole-run lock and the work directory. None of them reads
// HOME, XDG_CACHE_HOME or TMPDIR.
type HomeSeams struct {
	HomeDir   func() (string, error)
	Lock      func(repo, tag string) (release func() error, err error)
	MkWorkDir func() (string, error)
}

// NewHomeSeams builds the production seams from accountHome, the lookup of the
// account database's home directory (user.Current in main).
func NewHomeSeams(accountHome func() (string, error)) HomeSeams {
	return HomeSeams{
		HomeDir: accountHome,
		Lock: func(repo, tag string) (func() error, error) {
			home, err := accountHome()
			if err != nil {
				return nil, err
			}
			l, err := lock.AcquireForHome(home, repo, tag)
			if err != nil {
				return nil, err
			}
			return l.Release, nil
		},
		MkWorkDir: func() (string, error) {
			home, err := accountHome()
			if err != nil {
				return "", err
			}
			return lock.MkWorkDir(home)
		},
	}
}
