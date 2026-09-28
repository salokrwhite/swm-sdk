//go:build windows && (amd64 || 386)

package swm

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLanguageIdentityCompatibility(t *testing.T) {
	if os.Getenv("SWM_TEST_CROSS_LANGUAGE") != "1" {
		t.Skip("set SWM_TEST_CROSS_LANGUAGE=1 to run .NET cross-language identity tests")
	}
	helper := filepath.Join("testdata", "crosslang", "SwmCrossLanguageHelper.csproj")

	t.Run("GoIdentityReadByCSharp", func(t *testing.T) {
		appID := "00000000-0000-0000-0000-000000000502"
		store, err := newStateStore(appID, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		identity, err := loadOrCreateIdentity(appID, store)
		if err != nil {
			t.Fatal(err)
		}
		defer identity.key.Delete()
		result := runCrossLanguageHelper(t, helper, appID, store.directory)
		assertIdentityResult(t, result, identity.deviceID, identity.installID, identity.keyID, identity.keyThumbprint)
	})

	t.Run("CSharpIdentityReadByGo", func(t *testing.T) {
		appID := "00000000-0000-0000-0000-000000000503"
		directory := t.TempDir()
		csharpResult := runCrossLanguageHelper(t, helper, appID, directory)
		store, err := newStateStore(appID, directory)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := loadOrCreateIdentity(appID, store)
		if err != nil {
			t.Fatal(err)
		}
		defer identity.key.Delete()
		assertIdentityResult(
			t,
			csharpResult,
			identity.deviceID,
			identity.installID,
			identity.keyID,
			identity.keyThumbprint,
		)
	})
}

func runCrossLanguageHelper(t *testing.T, project, appID, directory string) map[string]string {
	t.Helper()
	command := exec.Command(
		"dotnet",
		"run",
		"--project", project,
		"-c", "Release",
		"--",
		appID,
		directory,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-language helper failed: %v\n%s", err, output)
	}
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if ok {
			result[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertIdentityResult(
	t *testing.T,
	result map[string]string,
	deviceID, installID, keyID, thumbprint string,
) {
	t.Helper()
	if result["device_id"] != deviceID ||
		result["install_id"] != installID ||
		result["key_id"] != keyID ||
		result["key_thumbprint"] != thumbprint {
		t.Fatalf(
			"cross-language identity mismatch: got device=%q install=%q key=%q thumbprint=%q, want device=%q install=%q key=%q thumbprint=%q",
			result["device_id"],
			result["install_id"],
			result["key_id"],
			result["key_thumbprint"],
			deviceID,
			installID,
			keyID,
			thumbprint,
		)
	}
}
