// Test Crypt filesystem interface
package cryptomator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/fstest/fstests"

	_ "github.com/rclone/rclone/backend/alias"
	_ "github.com/rclone/rclone/backend/local"
	_ "github.com/rclone/rclone/backend/s3"
	_ "github.com/rclone/rclone/backend/sftp"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	if *fstest.RemoteName == "" {
		t.Skip("Skipping as -remote not set")
	}
	fstests.Run(t, &fstests.Opt{
		RemoteName:                   *fstest.RemoteName,
		UnimplementableFsMethods:     []string{"OpenWriterAt"},
		UnimplementableObjectMethods: []string{"MimeType"},
		QuickTestOK:                  true,
		TiersToTest:                  []string{"REDUCED_REDUNDANCY", "STANDARD"},
	})
}

func TestStandard(t *testing.T) {
	if *fstest.RemoteName != "" {
		t.Skip("Skipping as -remote set")
	}
	tempdir := filepath.Join(os.TempDir(), "rclone-crypt-test-standard")
	name := "TestCryptomator"
	fstests.Run(t, &fstests.Opt{
		RemoteName: name + ":",
		ExtraConfig: []fstests.ExtraConfigItem{
			{Name: name, Key: "type", Value: "crypt"},
			{Name: name, Key: "remote", Value: tempdir},
			{Name: name, Key: "password", Value: obscure.MustObscure("potato")},
			{Name: name, Key: "filename_encryption", Value: "standard"},
		},
		UnimplementableFsMethods:     []string{"OpenWriterAt"},
		UnimplementableObjectMethods: []string{"MimeType"},
		QuickTestOK:                  true,
	})
}
