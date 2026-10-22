package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func (m *model) updateItem(msg tea.Msg) tea.Cmd {
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil
	}
	e := m.selected()
	if e == nil {
		m.st = stateVault
		return nil
	}
	n := len(m.visible())
	switch k.String() {
	case "esc", "backspace", "left", "h":
		m.hideReveal()
		m.st = m.itemBack
	case "up", "k": // step through credentials without going back to the list
		if m.list.cursor > 0 {
			m.list.cursor--
			m.hideReveal()
		}
	case "down", "j":
		if m.list.cursor < n-1 {
			m.list.cursor++
			m.hideReveal()
		}
	case "c", "y":
		return m.copyCmd(*e, "Password")
	case "u":
		return m.copyCmd(*e, "Username")
	case "v":
		m.reveal(e)
	case "e":
		m.openEdit(e)
	case "d", "x", "delete":
		m.openDelete(e)
	}
	return nil
}

func (m *model) viewItem() string {
	th := m.th
	w, _ := m.bodySize()
	e := m.selected()
	if e == nil {
		return m.chrome("", m.autoLockBar(), "", "ITEM", "esc", "back")
	}
	inner := min(w, 80)

	text, _, c := m.issue(e)
	icon := "! "
	if c == th.Ok {
		icon = "✓ "
	} else if c == th.Err {
		icon = "✕ "
	}
	head := m.avatar(e.SiteName, nil) + fg(th.Fg).Bold(true).Render(truncate(e.SiteName, inner-6)) +
		"\n    " + fg(c).Render(truncate(icon+text, inner-6))

	reveal := "v show"
	pw := fg(th.Muted).Render(strings.Repeat("•", 16))
	if m.revealed == e.ID {
		reveal = "v hide"
		pw = m.colorize(truncate(m.revealPw, inner-30))
	}
	row := func(label, value, keys string) string {
		return spread(fg(th.Muted).Width(12).Render(strings.ToUpper(label))+value, fg(th.Muted).Render(keys), inner)
	}
	updated := ago(e.UpdatedAt) + " ago"
	if updated == "now ago" {
		updated = "just now"
	}
	vis := m.visible()
	pos := fmt.Sprintf("%d of %d", m.list.cursor+1, len(vis))

	body := lipgloss.JoinVertical(lipgloss.Left,
		head,
		"",
		fg(th.Border).Render(strings.Repeat("─", inner)),
		row("Username", fg(th.Accent2).Render(truncate(e.user, inner-30)), "u copy"),
		row("Password", pw, "c copy · "+reveal),
		row("Strength", m.strengthBar(e.score), ""),
		row("Updated", fg(th.Fg).Render(updated), ""),
		row("Created", fg(th.Fg).Render(e.CreatedAt.Local().Format("2 Jan 2006")), ""),
		row("ID", fg(th.Muted).Render(e.ID[:min(8, len(e.ID))]), ""),
		fg(th.Border).Render(strings.Repeat("─", inner)),
		m.hints("e", "edit", "d", "delete", "↑↓", "prev/next"),
	)
	return m.chrome(m.crumbs(e.SiteName), fg(th.Muted).Render(pos+"  ")+m.autoLockBar(), body,
		"ITEM", "c", "copy", "u", "user", "v", "reveal", "e", "edit", "esc", "back")
}
