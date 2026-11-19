package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildTestBinary(t *testing.T) string {
	t.Helper()
	binName := "openpassport-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}
	return binPath
}

func runCLI(t *testing.T, binPath string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("executing %v failed unexpectedly: %v", args, err)
		}
	}
	return exitCode, stdout.String(), stderr.String()
}

func copyTemplateForCLI(t *testing.T, dst string) {
	t.Helper()
	src := filepath.Join("..", "..", "templates", "open-passport-template")
	err := filepath.Walk(src, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
	if err != nil {
		t.Fatalf("copyTemplateForCLI failed: %v", err)
	}
}

func TestCLI(t *testing.T) {
	binPath := buildTestBinary(t)

	t.Run("version", func(t *testing.T) {
		code, out, errOut := runCLI(t, binPath, "version")
		if code != 0 {
			t.Fatalf("version exit code = %d, want 0 (stderr=%s)", code, errOut)
		}
		if !strings.Contains(out, "openpassport CLI v") {
			t.Fatalf("unexpected version output: %q", out)
		}
	})

	t.Run("unknown_command_exit_2", func(t *testing.T) {
		code, _, errOut := runCLI(t, binPath, "nonexistent-command")
		if code != 2 {
			t.Fatalf("unknown command exit code = %d, want 2 (stderr=%s)", code, errOut)
		}
	})

	t.Run("verify_pass_exit_0_and_no_emoji", func(t *testing.T) {
		dir := t.TempDir()
		copyTemplateForCLI(t, dir)

		code, out, errOut := runCLI(t, binPath, "verify", dir, "--no-emoji")
		if code != 0 {
			t.Fatalf("verify pass exit code = %d, want 0 (out=%s, err=%s)", code, out, errOut)
		}
		if !strings.Contains(out, "[100% PASS]") {
			t.Fatalf("expected PASS message in output, got: %q", out)
		}
		for _, emoji := range []string{"🔒", "🎉", "✅", "❌", "💥"} {
			if strings.Contains(out, emoji) {
				t.Errorf("expected --no-emoji to suppress %q in output: %q", emoji, out)
			}
		}
	})

	t.Run("verify_tampered_exit_1", func(t *testing.T) {
		dir := t.TempDir()
		copyTemplateForCLI(t, dir)

		if err := os.WriteFile(filepath.Join(dir, "01-IDENTITY.md"), []byte("# TAMPERED\n"), 0644); err != nil {
			t.Fatalf("tampering file: %v", err)
		}

		code, out, _ := runCLI(t, binPath, "verify", dir, "--json")
		if code != 1 {
			t.Fatalf("verify tampered exit code = %d, want 1 (out=%s)", code, out)
		}

		var payload struct {
			Valid  bool     `json:"valid"`
			Errors []string `json:"errors"`
			Dir    string   `json:"dir"`
		}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("decoding verify JSON output: %v\nraw: %s", err, out)
		}
		if payload.Valid {
			t.Fatalf("expected JSON valid=false for tampered passport")
		}
		if len(payload.Errors) == 0 {
			t.Fatalf("expected non-empty errors in verify JSON output")
		}
	})

	t.Run("lint_json_pass_and_fail", func(t *testing.T) {
		dir := t.TempDir()
		copyTemplateForCLI(t, dir)

		code, out, _ := runCLI(t, binPath, "lint", dir, "--json")
		if code != 0 {
			t.Fatalf("lint pass exit code = %d, want 0 (out=%s)", code, out)
		}
		var passRes struct {
			Valid  bool     `json:"valid"`
			Issues []string `json:"issues"`
			Dir    string   `json:"dir"`
		}
		if err := json.Unmarshal([]byte(out), &passRes); err != nil {
			t.Fatalf("decoding lint JSON pass: %v\nraw: %s", err, out)
		}
		if !passRes.Valid || len(passRes.Issues) != 0 {
			t.Fatalf("expected valid=true and 0 issues, got: %+v", passRes)
		}

		// Introduce CRLF corruption to trigger lint failure
		if err := os.WriteFile(filepath.Join(dir, "02-DOCTRINE.md"), []byte("# Doctrine\r\n"), 0644); err != nil {
			t.Fatalf("writing CRLF file: %v", err)
		}
		code, out, _ = runCLI(t, binPath, "lint", dir, "--json")
		if code != 1 {
			t.Fatalf("lint fail exit code = %d, want 1 (out=%s)", code, out)
		}
		var failRes struct {
			Valid  bool     `json:"valid"`
			Issues []string `json:"issues"`
		}
		if err := json.Unmarshal([]byte(out), &failRes); err != nil {
			t.Fatalf("decoding lint JSON fail: %v\nraw: %s", err, out)
		}
		if failRes.Valid || len(failRes.Issues) == 0 {
			t.Fatalf("expected valid=false and non-empty issues, got: %+v", failRes)
		}
	})
}
