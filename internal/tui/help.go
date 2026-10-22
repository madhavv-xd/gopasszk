package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

func (m *model) viewHelp() string {
	th := m.th
	w, _ := m.bodySize()
	section := func(title string, pairs ...string) string {
		lines := []string{fg(th.Accent).Bold(true).Render(title)}
		for i := 0; i+1 < len(pairs); i += 2 {
			lines = append(lines, fg(th.Fg).Bold(true).Width(13).Render(pairs[i])+fg(th.Muted).Render(pairs[i+1]))
		}
		return strings.Join(lines, "\n")
	}
	left := lipgloss.JoinVertical(lipgloss.Left,
		section("Move", "↑↓ / j k", "up / down", "pgup pgdn", "page (ctrl+u / ctrl+d)", "g / G", "top / bottom",
			"enter / →", "open", "esc / ←", "back"),
		"",
		section("Find", "/ or ctrl+f", "search site or username", "esc", "clear search", "s", "sort: name ↔ recent"),
		"",
		section("Vault", "a / n", "add credential", "ctrl+g", "generate + copy a password", "A", "health audit",
			"r", "refresh", "p", "change master password"),
	)
	right := lipgloss.JoinVertical(lipgloss.Left,
		section("Credential", "c / y", "copy password", "u", "copy username", "v", "show / hide password",
			"e", "edit", "d / x / del", "delete"),
		"",
		section("Editing", "tab / enter", "next field", "ctrl+s", "save", "ctrl+g", "generate password",
			"←/→", "generated length", "ctrl+r", "show / hide password"),
		"",
		section("Session", "L / ctrl+l", "lock now", "O", "log out (forget this device)", "T", "theme: "+th.Name,
			"?", "this help", "q / ctrl+c", "quit"),
	)
	body := lipgloss.JoinVertical(lipgloss.Left, left, "", right)
	if w >= 76 {
		body = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(w/2).Render(left), right)
	}
	return m.chrome(m.crumbs("keys"), m.autoLockBar(), body, "HELP", "?", "close", "esc", "close")
}
