package tui

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

type webBrowserOpened struct{ err error }

func openWebBrowser(url string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var command *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			command = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
		case "darwin":
			command = exec.CommandContext(ctx, "open", url)
		default:
			command = exec.CommandContext(ctx, "xdg-open", url)
		}
		return webBrowserOpened{err: command.Run()}
	}
}

func (m model) viewWebConnect(w int) string {
	return headingStyle.Render("Web готов") + "\n\nБраузер открывается автоматически. Если он не открылся,\nскопируйте полную ссылку ниже:\n\n" + ansi.Hardwrap(m.webURL, max(1, w-2), false) + "\n\nO — открыть браузер ещё раз\nEnter — продолжить в TUI\n\nСервер работает, пока запущено приложение."
}

func (m model) updateWebConnect(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "o":
		return m, openWebBrowser(m.webURL)
	case "enter", "esc":
		m.screen = "projects"
	}
	return m, nil
}

func webOpenMessage(err error) string {
	if err != nil {
		return fmt.Sprintf("Браузер не открылся. Скопируйте ссылку; Enter — TUI. (%v)", err)
	}
	return "Ссылка передана браузеру. Enter — продолжить в TUI."
}
