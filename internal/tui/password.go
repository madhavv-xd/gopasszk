package tui

import (
	"bytes"
	"errors"
	"time"
	"unicode/utf8"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

type passwordState struct {
	fields [3]field // current, new, confirm
	focus  int
	busy   bool
	err    string
}

type pwChangedMsg struct {
	c   *client.Client
	err error
}

func (p *passwordState) wipe() {
	for i := range p.fields {
		p.fields[i].wipe()
	}
}

func (m *model) openPassword() {
	m.pw.wipe()
	m.pw = passwordState{fields: [3]field{
		{label: "Current password"},
		{label: "New password", placeholder: "at least 8 characters"},
		{label: "Confirm new password", placeholder: "retype to confirm"},
	}}
	m.st = statePassword
}

func (m *model) updatePassword(msg tea.Msg) tea.Cmd {
	p := &m.pw
	switch msg := msg.(type) {
	case pwChangedMsg:
		p.busy = false
		if errors.Is(msg.err, vault.ErrWrongPassword) {
			p.err, p.focus = "Wrong master password", 0
			return nil
		}
		if msg.err != nil {
			p.err = msg.err.Error()
			return m.fail(msg.err)
		}
		m.c = msg.c // fresh token
		m.st = stateVault
		m.notify("Master password changed", "Your vault key was re-wrapped", false, 4*time.Second)

	case tea.PasteMsg:
		if !p.busy {
			f := &p.fields[p.focus]
			f.buf = appendSecret(f.buf, msg.Content)
		}

	case tea.KeyPressMsg:
		if p.busy {
			return nil
		}
		p.err = ""
		switch msg.String() {
		case "tab", "down":
			p.focus = (p.focus + 1) % len(p.fields)
		case "shift+tab", "up":
			p.focus = (p.focus + len(p.fields) - 1) % len(p.fields)
		case "esc":
			p.wipe()
			m.st = stateVault
		case "enter":
			if p.focus < len(p.fields)-1 {
				p.focus++
				return nil
			}
			return m.submitPassword()
		default:
			p.fields[p.focus].edit(msg)
		}
	}
	return nil
}

func (m *model) submitPassword() tea.Cmd {
	p := &m.pw
	for i, f := range p.fields {
		if len(f.buf) == 0 {
			p.err, p.focus = "Fill in every field", i
			return nil
		}
	}
	if !bytes.Equal(p.fields[1].buf, p.fields[2].buf) {
		p.err, p.focus = "New passwords don't match", 2
		return nil
	}
	if utf8.RuneCount(p.fields[1].buf) < 8 {
		p.err, p.focus = "Use at least 8 characters", 1
		return nil
	}
	// Hand the buffers to the command, which zeroes them when done.
	oldPw, newPw, confirm := p.fields[0].buf, p.fields[1].buf, p.fields[2].buf
	for i := range p.fields {
		p.fields[i].buf = nil
	}
	p.busy = true
	server, email, onLogin := m.server, m.auth.email, m.onLogin
	return func() tea.Msg {
		defer clear(oldPw)
		defer clear(newPw)
		defer clear(confirm)
		c, err := vault.ChangePassword(server, email, oldPw, newPw)
		if err == nil && onLogin != nil {
			onLogin(email, c.Token)
		}
		return pwChangedMsg{c, err}
	}
}

func (m *model) viewPassword() string {
	th, p := m.th, &m.pw
	w, _ := m.bodySize()
	fw := min(44, w)
	var parts []string
	for i := range p.fields {
		parts = append(parts, m.input(&p.fields[i], i == p.focus && !p.busy, fw, false), "")
	}
	parts = append(parts, fg(th.Muted).Render("Only your vault key is re-wrapped. Saved credentials are not re-encrypted."))
	switch {
	case p.busy:
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		parts = append(parts, "", fg(th.Accent).Render(spin)+fg(th.Muted).Render("re-wrapping your vault key…"),
			bounceBar(m.frame, fw, th.Accent, th.Border))
	case p.err != "":
		parts = append(parts, "", fg(th.Err).Render(p.err))
	}
	return m.chrome(m.crumbs("change master password"), m.autoLockBar(),
		lipgloss.JoinVertical(lipgloss.Left, parts...),
		"PASSWORD", "tab", "next field", "enter", "change", "esc", "cancel")
}
