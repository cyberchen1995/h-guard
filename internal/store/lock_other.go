//go:build !unix && !windows

package store

import (
	"errors"
	"os"
)

func lockFile(*os.File) error   { return errors.ErrUnsupported }
func unlockFile(*os.File) error { return nil }
