package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// generatePSK returns a fresh 32-byte base64 key.
func generatePSK() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// runWizard implements the interactive setup mode: `openflux` without
// arguments asks for all required parameters step by step, shows the
// equivalent CLI command, and on confirmation replays the answers through
// the regular flag-based entry point (runArgs), so no startup logic is
// duplicated.
func runWizard() error {
	args, err := wizardArgs(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return nil // aborted (EOF on stdin)
	}
	return runArgs(args)
}

// wizardArgs interactively collects settings from in/out and returns the
// equivalent CLI argument vector. A nil slice (with nil error) means the
// input ended before the setup was confirmed (abort).
func wizardArgs(in io.Reader, out io.Writer) ([]string, error) {
	r := bufio.NewReader(in)

	// ask prints a prompt and returns the trimmed answer; ok=false means
	// stdin ended before any input on this question (treated as abort).
	ask := func(prompt string) (string, bool) {
		fmt.Fprint(out, prompt)
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			return "", false
		}
		return line, true
	}

	askChoice := func(prompt string, min, max int) (int, bool) {
		for {
			s, ok := ask(prompt)
			if !ok {
				return 0, false
			}
			if n, err := strconv.Atoi(s); err == nil && n >= min && n <= max {
				return n, true
			}
			fmt.Fprintf(out, "  ! Введите число от %d до %d.\n", min, max)
		}
	}

	askYesNo := func(prompt string, def bool) (bool, bool) {
		hint := "[д/Н]"
		if def {
			hint = "[Д/н]"
		}
		for {
			s, ok := ask(prompt + " " + hint + ": ")
			if !ok {
				return false, false
			}
			switch strings.ToLower(s) {
			case "":
				return def, true
			case "д", "да", "y", "yes":
				return true, true
			case "н", "нет", "n", "no":
				return false, true
			}
			fmt.Fprintln(out, `  ! Ответьте "да" или "нет" (y/n).`)
		}
	}

	fmt.Fprintln(out, "=== OpenFlux: мастер настройки (wizard) ===")
	fmt.Fprintln(out, "Отвечайте на вопросы; Ctrl+C — выход в любой момент.")
	fmt.Fprintln(out)

	// 1. Mode.
	fmt.Fprintln(out, "Режим работы:")
	fmt.Fprintln(out, "  [1] client    — локальный SOCKS5-прокси (ваш компьютер)")
	fmt.Fprintln(out, "  [2] exit node — выходная нода (сервер с доступом в интернет)")
	mode, ok := askChoice("Выбор [1-2]: ", 1, 2)
	if !ok {
		return nil, nil
	}
	isClient := mode == 1

	// 2. Carrier (friendly names; mapped to internal transport names below).
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Carrier (транспорт):")
	fmt.Fprintln(out, "  [1] direct — быстрый, свой сервер (прямое TCP-соединение)")
	fmt.Fprintln(out, "  [2] yandex — через Яндекс Документы (OnlyOffice)")
	fmt.Fprintln(out, "  [3] mail   — через Mail.ru Облако")
	fmt.Fprintln(out, "  [4] max    — MAX messenger (экспериментальный)")
	carrier, ok := askChoice("Выбор [1-4]: ", 1, 4)
	if !ok {
		return nil, nil
	}

	args := []string{"exit"}
	if isClient {
		args[0] = "client"
	}

	// 3. Carrier-specific questions.
	fmt.Fprintln(out)
	switch carrier {
	case 1: // direct
		args = append(args, "--transport", "direct")
		prompt, def := "Адрес выходной ноды (IP:port): ", ""
		if !isClient {
			prompt, def = "Listen-адрес [0.0.0.0:9000]: ", "0.0.0.0:9000"
		}
		for {
			s, ok := ask(prompt)
			if !ok {
				return nil, nil
			}
			if s == "" {
				s = def
			}
			if s != "" {
				args = append(args, "--addr", s)
				break
			}
			fmt.Fprintln(out, "  ! Адрес не может быть пустым.")
		}
	case 2, 3: // yandex -> auto-detect, mail -> "mail"
		transportName, hint := "yandex", "публичная ссылка на документ Яндекс Диска (редактор определится сам)"
		if carrier == 3 {
			transportName, hint = "mail", "публичная ссылка на документ в Mail.ru Облаке"
		}
		args = append(args, "--transport", transportName)
		for {
			s, ok := ask("URL документа (" + hint + "): ")
			if !ok {
				return nil, nil
			}
			if s != "" {
				args = append(args, "--url", s)
				break
			}
			fmt.Fprintln(out, "  ! URL не может быть пустым.")
		}
	case 4: // max -> "oneme"
		args = append(args, "--transport", "oneme")
		for {
			s, ok := ask("MAX Web token (maxToken): ")
			if !ok {
				return nil, nil
			}
			if s != "" {
				args = append(args, "--maxToken", s)
				break
			}
			fmt.Fprintln(out, "  ! Token не может быть пустым.")
		}
		for {
			s, ok := ask("MAX call user id (maxUid, число): ")
			if !ok {
				return nil, nil
			}
			if _, err := strconv.ParseInt(s, 10, 64); err == nil {
				args = append(args, "--maxUid", s)
				break
			}
			fmt.Fprintln(out, "  ! maxUid должен быть числом.")
		}
	}

	// 4. PSK: env first; otherwise generate / paste / insecure.
	fmt.Fprintln(out)
	if envPSK := os.Getenv("OPENFLUX_PSK"); envPSK != "" {
		fmt.Fprintln(out, "PSK найден в env OPENFLUX_PSK — использую его.")
		args = append(args, "--psk", envPSK)
	} else {
		fmt.Fprintln(out, "PSK-ключ (общий секрет клиента и ноды):")
		fmt.Fprintln(out, "  [1] Сгенерировать новый (покажу — скопируешь на вторую машину)")
		fmt.Fprintln(out, "  [2] Вставить существующий")
		fmt.Fprintln(out, "  [3] Без шифрования (только тестирование)")
		for {
			choice, ok := ask("Выбор [1-3]: ")
			if !ok {
				return nil, nil
			}
			switch choice {
			case "1":
				psk := generatePSK()
				fmt.Fprintf(out, "Сгенерированный PSK — скопируй его на вторую машину:\n  %s\n", psk)
				args = append(args, "--psk", psk)
			case "2":
				s, ok := ask("PSK: ")
				if !ok {
					return nil, nil
				}
				if s == "" {
					fmt.Fprintln(out, "  ! Пустой PSK.")
					continue
				}
				args = append(args, "--psk", s)
			case "3":
				args = append(args, "--insecure")
			default:
				fmt.Fprintln(out, "  ! Введите 1, 2 или 3.")
				continue
			}
			break
		}
	}

	// 5. Debug.
	debugPrompt := "Включить debug-лог?"
	if !isClient {
		debugPrompt = "Включить debug-лог (для exit-ноды полезен при диагностике)?"
	}
	debug, ok := askYesNo(debugPrompt, false)
	if !ok {
		return nil, nil
	}
	if debug {
		args = append(args, "--debug")
	}

	// 6. SOCKS5 listen address (client only).
	if isClient {
		fmt.Fprintln(out)
		s, ok := ask("SOCKS5 listen-адрес [127.0.0.1:1080]: ")
		if !ok {
			return nil, nil
		}
		if s == "" {
			s = "127.0.0.1:1080"
		}
		args = append(args, "--socks5", s)
	}

	// Summary + confirmation.
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Эквивалентная команда:")
	fmt.Fprintf(out, "  openflux %s\n", maskSecrets(args))
	fmt.Fprintln(out)
	if _, ok := ask("Enter — запустить, Ctrl+C — отмена "); !ok {
		return nil, nil
	}
	return args, nil
}

// maskSecrets renders args as a command line for display, hiding secret
// flag values (PSK, tokens) — secrets must not end up in logs/output.
func maskSecrets(args []string) string {
	secretValue := map[string]bool{"--psk": true, "--maxToken": true}
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
			if secretValue[args[i-1]] {
				b.WriteString("***")
				continue
			}
		}
		if strings.ContainsAny(a, " \t\"") {
			fmt.Fprintf(&b, "%q", a)
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}
