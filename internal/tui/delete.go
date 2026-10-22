package tui

import (
	"slices"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type deleteState struct {
	id, site string
	input    field
	busy     bool
	err      string
}

type deletedMsg struct {
	id, site string
	err      error
}

func (m *model) openDelete(e *entry) {
	m.del.input.wipe()
	m.del = deleteState{id: e.ID, site: e.SiteName, input: field{plain: true, placeholder: e.SiteName}}
	m.hideReveal()
	m.back, m.st = m.st, stateDelete
}

func (m *model) updateDelete(msg tea.Msg) tea.Cmd {
	d := &m.del
	switch msg := msg.(type) {
	case deletedMsg:
		d.busy = false
		if msg.err != nil {
			d.err = msg.err.Error()
			return m.fail(msg.err)
		}
		m.entries = slices.DeleteFunc(m.entries, func(e entry) bool { return e.ID == msg.id })
		delete(m.breached, msg.id)
		m.list.clamp(m)
		m.st = stateVault
		m.notify("Deleted "+msg.site, "Removed from your vault", false, 3*time.Second)
	case tea.KeyPressMsg:
		if d.busy {
			return nil
		}
		d.err = ""
		switch msg.String() {
		case "esc":
			d.input.wipe()
			m.st = m.back
		case "enter":
			if string(d.input.buf) != d.site {
				d.err = "Type the site name exactly to confirm"
				return nil
			}
			d.busy = true
			c, id, site := m.c, d.id, d.site
			return func() tea.Msg { return deletedMsg{id, site, c.DeleteCredential(id)} }
		default:
			d.input.edit(msg)
		}
	}
	return nil
}

func (m *model) viewDelete() string {
	th, d := m.th, &m.del
	w, _ := m.bodySize()
	cw := min(64, w)
	matches := string(d.input.buf) == d.site

	status := ""
	switch {
	case d.busy:
		status = fg(th.Accent).Render(spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]) + fg(th.Muted).Render("deleting…")
	case d.err != "":
		status = fg(th.Err).Render(d.err)
	case matches:
		status = fg(th.Ok).Render("✓ name matches, press enter to delete")
	}
	box := m.card(lipgloss.JoinVertical(lipgloss.Left,
		fg(th.Err).Bold(true).Render("✕ Delete credential"),
		"",
		fg(th.Fg).Width(cw-6).Render("This permanently removes "+fg(th.Fg).Bold(true).Render(d.site)+
			" from your vault. It can't be undone."),
		"",
		fg(th.Muted).Render("Type the site name to confirm"),
		m.input(&d.input, !d.busy, min(cw-6, 40), d.err != ""),
		status,
	), cw, th.Err)

	return m.chrome(m.crumbs(truncate(d.site, 24), "delete"), m.autoLockBar(), "\n"+box,
		"DELETE", "enter", "delete (when the name matches)", "esc", "cancel")
}
