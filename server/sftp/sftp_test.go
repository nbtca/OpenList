package sftp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/server/ftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDriverAdapter tests the DriverAdapter directly
func TestDriverAdapter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sftp-driver-test-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err, "Failed to create test file")

	testDir := filepath.Join(tempDir, "testdir")
	err = os.MkdirAll(testDir, 0755)
	require.NoError(t, err, "Failed to create test directory")

	ctx := context.Background()
	testUser := &model.User{
		ID:         1,
		Username:   "test",
		Permission: 0b111111111111111,
		BasePath:   tempDir,
	}
	ctx = context.WithValue(ctx, conf.UserKey, testUser)

	ftpDriver := ftp.NewAferoAdapter(ctx)
	adapter := &DriverAdapter{
		FtpDriver: ftpDriver,
	}

	t.Run("RealPath", func(t *testing.T) {
		result, err := adapter.RealPath("/test")
		assert.NoError(t, err, "RealPath should not return error")
		assert.Equal(t, "/test", result, "RealPath should return cleaned path")
	})

	t.Run("SetStat", func(t *testing.T) {
		err := adapter.SetStat("/test", nil)
		assert.NoError(t, err, "SetStat should return nil (no-op)")
	})
}

// TestSftpFlagToOpenMode tests the sftpFlagToOpenMode function
func TestSftpFlagToOpenMode(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint32
		expected int
	}{
		{
			name:     "Read only",
			flags:    SSH_FXF_READ,
			expected: os.O_RDONLY,
		},
		{
			name:     "Write only",
			flags:    SSH_FXF_WRITE,
			expected: os.O_WRONLY,
		},
		{
			name:     "Create",
			flags:    SSH_FXF_WRITE | SSH_FXF_CREAT,
			expected: os.O_WRONLY | os.O_CREATE,
		},
		{
			name:     "Create and truncate",
			flags:    SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
			expected: os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
		},
		{
			name:     "Create exclusive",
			flags:    SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
			expected: os.O_WRONLY | os.O_CREATE | os.O_EXCL,
		},
		{
			name:     "Append",
			flags:    SSH_FXF_WRITE | SSH_FXF_APPEND,
			expected: os.O_WRONLY | os.O_APPEND,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sftpFlagToOpenMode(tt.flags)
			assert.Equal(t, tt.expected, result, "Flags should match expected")
		})
	}
}
