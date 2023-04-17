// Test Crypt filesystem interface
package cryptomator_test

import (
	"testing"

	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/fstest/fstests"

  _ "github.com/rclone/rclone/backend/alias"
  _ "github.com/rclone/rclone/backend/local"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	if *fstest.RemoteName == "" {
		t.Skip("Skipping as -remote not set")
	}
	fstests.Run(t, &fstests.Opt{
		RemoteName:                   *fstest.RemoteName,
	})
}
