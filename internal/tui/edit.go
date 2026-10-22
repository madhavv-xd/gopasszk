package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/madhavv-xd/gopasszk/internal/pwgn"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

const (
	minLen = 8
	maxLen = 64
)

type editState struct {
	id        string // "" adds a new credential
	site      string // original site name, for the breadcrumb
	fields    [3]field
	focus     int
	length    int
	generated bool // the password came from the generator, so ←/→ regenerates it
	busy      bool
	err       string
}

type savedMsg struct {
	id, site string
	err      error
}

func (ed *editState) wipe() {
	for i := range ed.fields {
		ed.fields[i].wipe()
	}
}

// openEdit opens the form for e, or for a new credential when e is nil.
func (m *model) openEdit(e *entry) {
	m.edit.wipe()
	ed := editState{length: 20, fields: [3]field{
		{label: "Site", plain: true, placeholder: "github"},
		{label: "Username", plain: true, placeholder: "you@example.com"},
		{label: "Password", colored: true, placeholder: "leave blank to generate"},
	}}
	if e != nil {
		pw, err := vault.DecryptField(m.key, e.PasswordCiphertext)
		if err != nil {
			m.notify("Could not decrypt", err.Error(), true, 4*time.Second)
			return
		}
		ed.id, ed.site = e.ID, e.SiteName
		ed.fields[0].set(e.SiteName)
		ed.fields[1].set(e.user)
		ed.fields[2].set(pw)
		ed.fields[2].colored = false // an existing password starts masked; ctrl+r shows it
	}
	m.edit = ed
	m.hideReveal()
	m.back, m.st = m.st, stateEdit
}

func (m *model) generate() {
	ed := &m.edit
	pw, err := pwgn.Generate(ed.length)
	if err != nil {
		ed.err = err.Error()
		return
	}
	ed.fields[2].set(pw)
	ed.fields[2].colored = true // show what was generated
	ed.generated = true
}

func (m *model) updateEdit(msg tea.Msg) tea.Cmd {
	ed := &m.edit
	switch msg := msg.(type) {
	case savedMsg:
		ed.busy = false
		if msg.err != nil {
			ed.err = msg.err.Error()
			return m.fail(msg.err)
		}
		delete(m.breached, msg.id) // the password may have changed
		m.edit.wipe()
		m.list.filter.wipe() // so the saved credential is visible and selected
		m.list.want = msg.id
		m.st = stateVault
		if m.back == stateItem {
			m.st = stateItem
		}
		m.notify("Saved "+msg.site, "Encrypted on this device", false, 3*time.Second)
		return m.loadCmd()

	case tea.PasteMsg:
		if !ed.busy {
			f := &ed.fields[ed.focus]
			f.buf = appendSecret(f.buf, msg.Content)
		}

	case tea.KeyPressMsg:
		if ed.busy {
			return nil
		}
		ed.err = ""
		switch msg.String() {
		case "tab", "down":
			ed.focus = (ed.focus + 1) % len(ed.fields)
		case "shift+tab", "up":
			ed.focus = (ed.focus + len(ed.fields) - 1) % len(ed.fields)
		case "esc":
			m.edit.wipe()
			m.st = m.back
		case "ctrl+g":
			m.generate()
		case "ctrl+r":
			ed.fields[2].colored = !ed.fields[2].colored
		case "left", "right":
			if msg.String() == "left" {
				ed.length = max(ed.length-1, minLen)
			} else {
				ed.length = min(ed.length+1, maxLen)
			}
			if ed.generated {
				m.generate()
			}
		case "enter": // next field; save from the last one
			if ed.focus < len(ed.fields)-1 {
				ed.focus++
				return nil
			}
			return m.saveEdit()
		case "ctrl+s":
			return m.saveEdit()
		default:
			if ed.fields[ed.focus].edit(msg) && ed.focus == 2 {
				ed.generated = false
			}
		}
	}
	return nil
}

// saveEdit encrypts on this device, then sends only ciphertext to the server.
func (m *model) saveEdit() tea.Cmd {
	ed := &m.edit
	site := strings.TrimSpace(string(ed.fields[0].buf))
	if site == "" {
		ed.err, ed.focus = "Site is required", 0
		return nil
	}
	if len(ed.fields[2].buf) == 0 {
		m.generate()
	}
	userCT, err := vault.EncryptField(m.key, string(ed.fields[1].buf))
	if err != nil {
		ed.err = err.Error()
		return nil
	}
	passCT, err := vault.EncryptField(m.key, string(ed.fields[2].buf))
	if err != nil {
		ed.err = err.Error()
		return nil
	}
	ed.busy = true
	c, id := m.c, ed.id
	return func() tea.Msg {
		if id == "" {
			cr, err := c.CreateCredential(site, userCT, passCT)
			return savedMsg{id: cr.ID, site: site, err: err}
		}
		return savedMsg{id: id, site: site, err: c.UpdateCredential(id, site, userCT, passCT)}
	}
}

func (m *model) viewEdit() string {
	th, ed := m.th, &m.edit
	w, _ := m.bodySize()
	const genW = 32
	wide := w >= 84
	formW := w
	if wide {
		formW = w - genW - 2
	}
	inputW := min(formW-2, 60)

	var parts []string
	for i := range ed.fields {
		parts = append(parts, m.input(&ed.fields[i], i == ed.focus && !ed.busy, inputW, false), "")
	}
	pw := ed.fields[2].buf
	if len(pw) > 0 {
		parts[len(parts)-1] = m.strengthBar(strength(pw))
	} else {
		parts[len(parts)-1] = fg(th.Muted).Render(fmt.Sprintf("generated length: %d", ed.length))
	}
	switch {
	case ed.busy:
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		parts = append(parts, "", fg(th.Accent).Render(spin)+fg(th.Muted).Render("encrypting and saving…"))
	case ed.err != "":
		parts = append(parts, "", fg(th.Err).Render(ed.err))
	}
	form := lipgloss.NewStyle().Width(formW).Render(lipgloss.JoinVertical(lipgloss.Left, parts...))

	body := form
	if wide {
		show := "ctrl+r show"
		if ed.fields[2].colored {
			show = "ctrl+r hide"
		}
		gen := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(th.Border).PaddingLeft(2).Width(genW).Render(lipgloss.JoinVertical(lipgloss.Left,
			spread(m.label("Generator length"), fg(th.Accent).Bold(true).Render(fmt.Sprint(ed.length)), genW-3),
			m.meter(ed.length, maxLen, genW-3, th.Accent),
			fg(th.Muted).Render("←/→ adjust"),
			"",
			fg(th.Muted).Render("a-z A-Z 0-9 !@#$…"),
			"",
			m.hints("ctrl+g", "generate"),
			m.hints("ctrl+r", strings.TrimPrefix(show, "ctrl+r ")),
			m.hints("ctrl+s", "save"),
		))
		body = lipgloss.JoinHorizontal(lipgloss.Top, form, "  ", gen)
	}

	title := m.crumbs("new credential")
	if ed.id != "" {
		title = m.crumbs("edit " + ed.site)
	}
	return m.chrome(title, m.autoLockBar(), body,
		"EDIT", "tab", "next", "enter", "next/save", "ctrl+s", "save", "ctrl+g", "generate", "esc", "cancel")
}
