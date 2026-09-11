package main

import (
	"bytes"
	"strings"
	"testing"
)

// runWizardScript feeds the scripted answers through wizardArgs and
// returns the built args plus everything the wizard printed.
func runWizardScript(t *testing.T, script string) ([]string, string) {
	t.Helper()
	var out bytes.Buffer
	args, err := wizardArgs(strings.NewReader(script), &out)
	if err != nil {
		t.Fatalf("wizardArgs: %v", err)
	}
	return args, out.String()
}

func TestWizardClientDirectInsecure(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	args, out := runWizardScript(t, "1\n1\n127.0.0.1:1\n3\n\n\n\n")
	want := []string{"client", "--transport", "direct", "--addr", "127.0.0.1:1",
		"--insecure", "--socks5", "127.0.0.1:1080"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
	if !strings.Contains(out, "openflux client --transport direct") {
		t.Fatalf("summary command missing from output:\n%s", out)
	}
}

func TestWizardExitYandexPSK(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	args, out := runWizardScript(t, "2\n2\nhttps://disk.yandex.ru/i/abc\n2\nshort\n\n\n")
	want := []string{"exit", "--transport", "onlyoffice", "--url",
		"https://disk.yandex.ru/i/abc", "--psk", "short"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
	// The PSK must be masked in the displayed summary command.
	if strings.Contains(out, "--psk short") {
		t.Fatalf("PSK leaked into summary:\n%s", out)
	}
	if !strings.Contains(out, "--psk ***") {
		t.Fatalf("masked PSK missing from summary:\n%s", out)
	}
}

func TestWizardInvalidChoiceRepeats(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	// "abc" and "7" are invalid mode choices; the wizard must ask again.
	args, out := runWizardScript(t, "abc\n7\n1\n1\n127.0.0.1:1\n3\n\n\n\n")
	if len(args) == 0 {
		t.Fatal("wizard aborted on invalid input")
	}
	if strings.Count(out, "Введите число от 1 до 2") != 2 {
		t.Fatalf("expected 2 re-prompts, output:\n%s", out)
	}
}

func TestWizardEmptyURLRepeats(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	args, _ := runWizardScript(t, "2\n3\n\nhttps://cloud.mail.ru/public/abc\n3\n\n\n")
	want := []string{"exit", "--transport", "mail", "--url",
		"https://cloud.mail.ru/public/abc", "--insecure"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestWizardMaxUIDValidation(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	args, out := runWizardScript(t, "1\n4\ntok123\nnotanumber\n42\n3\n\n\n\n")
	want := []string{"client", "--transport", "oneme", "--maxToken", "tok123",
		"--maxUid", "42", "--insecure", "--socks5", "127.0.0.1:1080"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
	if !strings.Contains(out, "maxUid должен быть числом") {
		t.Fatalf("maxUid validation message missing:\n%s", out)
	}
	if strings.Contains(out, "tok123 ") && strings.Contains(out, "--maxToken tok123") {
		t.Fatalf("maxToken leaked into summary:\n%s", out)
	}
}

func TestWizardPSKFromEnv(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "envkey")
	args, out := runWizardScript(t, "2\n1\n\n\n\n")
	want := []string{"exit", "--transport", "direct", "--addr", "0.0.0.0:9000",
		"--psk", "envkey"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
	if !strings.Contains(out, "OPENFLUX_PSK") {
		t.Fatalf("env notice missing:\n%s", out)
	}
}

func TestWizardEOFAborts(t *testing.T) {
	t.Setenv("OPENFLUX_PSK", "")
	args, _ := runWizardScript(t, "1\n") // stdin ends mid-setup
	if args != nil {
		t.Fatalf("args = %v, want nil (abort)", args)
	}
}

func TestMaskSecrets(t *testing.T) {
	got := maskSecrets([]string{"client", "--transport", "oneme", "--maxToken", "secret", "--maxUid", "7"})
	if strings.Contains(got, "secret") {
		t.Fatalf("secret not masked: %q", got)
	}
	if !strings.Contains(got, "--maxToken ***") {
		t.Fatalf("unexpected mask output: %q", got)
	}
}
