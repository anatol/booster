package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeLibsystemdShared points the host systemd version probe at an empty dir.
func fakeLibsystemdShared(t *testing.T) string {
	lib := t.TempDir()
	oldGlobs := libsystemdSharedGlobs
	libsystemdSharedGlobs = []string{filepath.Join(lib, "libsystemd-shared-*.so")}
	t.Cleanup(func() { libsystemdSharedGlobs = oldGlobs })
	return lib
}

// The image must carry the definitions systemd would load on the host: the
// highest-precedence copy of each name, with masked names left out, because
// init initializes exactly what it finds under /usr/lib/nvpcr.
func TestAppendNvPCRDefinitions(t *testing.T) {
	etc, usr := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(usr, "hardware.nvpcr"), []byte(`{"name":"hardware","nvIndex":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(usr, "login.nvpcr"), []byte(`{"name":"login","nvIndex":2}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(usr, "verity.nvpcr"), []byte(`{"name":"verity","nvIndex":3}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(usr, "README"), []byte("not a definition"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(etc, "login.nvpcr"), []byte(`{"name":"login","nvIndex":9}`), 0o644))
	require.NoError(t, os.Symlink("/dev/null", filepath.Join(etc, "verity.nvpcr")))

	lib := fakeLibsystemdShared(t)
	require.NoError(t, os.WriteFile(filepath.Join(lib, "libsystemd-shared-262-1.so"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(lib, "libsystemd-shared-261-1.so"), nil, 0o644))

	img, f := newTestImage(t)
	require.NoError(t, img.appendNvPCRDefinitions([]string{etc, filepath.Join(t.TempDir(), "absent"), usr}))
	require.True(t, img.contains["/usr/lib/nvpcr/hardware.nvpcr"])
	require.False(t, img.contains["/usr/lib/nvpcr/verity.nvpcr"], "masked in /etc")
	require.False(t, img.contains["/usr/lib/nvpcr/README"])
	require.Equal(t, `{"name":"login","nvIndex":9}`, string(readImageFile(t, img, f, "/usr/lib/nvpcr/login.nvpcr")))
}

// systemd 259 to 261 set up NvPCRs on the host with an anchor secret and reject
// an index defined the 262 way, so their definitions must stay out of the image.
func TestAppendNvPCRDefinitionsBefore262(t *testing.T) {
	usr, lib := t.TempDir(), fakeLibsystemdShared(t)
	require.NoError(t, os.WriteFile(filepath.Join(usr, "hardware.nvpcr"), []byte(`{"name":"hardware","nvIndex":1}`), 0o644))

	for _, lib261 := range []string{"libsystemd-shared-261.3-1.so", ""} {
		if lib261 != "" {
			require.NoError(t, os.WriteFile(filepath.Join(lib, lib261), nil, 0o644))
		}
		img, _ := newTestImage(t)
		require.NoError(t, img.appendNvPCRDefinitions([]string{usr}))
		require.False(t, img.contains["/usr/lib/nvpcr/hardware.nvpcr"], lib261)
	}
}

// Each distro's libsystemd-shared must be found, or its images silently get no
// NvPCR definitions.
func TestLibsystemdSharedGlobs(t *testing.T) {
	for _, lib := range []string{
		"/usr/lib/systemd/libsystemd-shared-262-1.so",
		"/usr/lib64/systemd/libsystemd-shared-262.1-1.fc44.so",
		"/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-262.so",
	} {
		matched := false
		for _, g := range libsystemdSharedGlobs {
			if ok, _ := filepath.Match(g, lib); ok {
				matched = true
			}
		}
		require.True(t, matched, lib)
	}
}
