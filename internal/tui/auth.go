package tui

import (
	"bytes"
	"fmt"
	"image/color"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

var lockClosed = []string{
	"     ",
	" ╭─╮ ",
	"╭┴─┴╮",
	"│ ● │",
	"╰───╯",
}

var lockOpen = []string{
	" ╭─╮ ",
	" │ ╵ ",
	"╭┴──╮",
	"│ ● │",
	"╰───╯",
}

type authMode int

const (
	modeLogin authMode = iota
	modeRegister
	modeRecover
	modePhrase // showing a new account's recovery phrase
)

type phase int

const (
	phaseIdle phase = iota
	phaseWorking
	phaseFailed
	phaseOpened
)

const openFrames = 10 // how long the open lock shows before the vault

type link struct {
	label string
	key   string // shortcut shown next to the label
	do    func(m *model) tea.Cmd
}

type authState struct {
	mode        authMode
	fields      []field
	links       []link
	focus       int // < len(fields) is a field, otherwise links[focus-len(fields)]
	phase       phase
	msg         string // error line (phaseFailed)
	openedAt    int
	email       string // the account in use; prefills the next form
	lockedTitle string // set when the vault was locked rather than freshly opened
	phrase      string // modePhrase only; dropped once acknowledged
}

type authDoneMsg struct {
	c      *client.Client
	key    []byte
	phrase string // set after a successful register, even if the login after it failed
	err    error
}

func newAuth(email string) authState {
	a := authState{email: email}
	a.setMode(modeLogin)
	return a
}

func goTo(mode authMode) func(*model) tea.Cmd {
	return func(m *model) tea.Cmd {
		m.auth.setMode(mode)
		return nil
	}
}

func (a *authState) setMode(mode authMode) {
	a.wipe()
	a.mode, a.phase, a.msg, a.lockedTitle = mode, phaseIdle, "", ""
	email := field{label: "Email", plain: true, placeholder: "you@example.com", buf: []byte(a.email)}
	back := []link{{"back to login", "esc", goTo(modeLogin)}}
	switch mode {
	case modeLogin:
		a.fields = []field{{label: "Master password"}}
		a.links = []link{{"create account", "ctrl+n", goTo(modeRegister)}, {"forgot password", "ctrl+r", goTo(modeRecover)}}
		if a.email == "" {
			a.fields = append([]field{email}, a.fields...)
		} else {
			a.links = append(a.links, link{"log out", "ctrl+o", (*model).logout})
		}
	case modeRegister:
		a.fields = []field{email, {label: "Master password", placeholder: "at least 8 characters"}, {label: "Confirm password"}}
		a.links = back
	case modeRecover:
		a.fields = []field{email, {label: "Recovery phrase", words: true, placeholder: "your 24 words"},
			{label: "New master password"}, {label: "Confirm new password"}}
		a.links = back
	default:
		a.fields, a.links = nil, nil
	}
	a.focus = 0
	for i, f := range a.fields { // start on the first empty field
		if len(f.buf) == 0 {
			a.focus = i
			break
		}
	}
}

// wipe zeroes every field, first remembering a typed email for the next form.
func (a *authState) wipe() {
	for i := range a.fields {
		if a.fields[i].label == "Email" && a.fields[i].buf != nil {
			a.email = strings.TrimSpace(string(a.fields[i].buf))
		}
		a.fields[i].wipe()
	}
	a.phrase = ""
}

func (a *authState) focused() *field {
	if a.focus < len(a.fields) {
		return &a.fields[a.focus]
	}
	return nil
}

func (a *authState) fail(msg string) tea.Cmd {
	a.phase, a.msg = phaseFailed, msg
	return nil
}

func (m *model) updateAuth(msg tea.Msg) tea.Cmd {
	a := &m.auth
	busy := a.phase == phaseWorking || a.phase == phaseOpened

	switch msg := msg.(type) {
	case authDoneMsg:
		var load tea.Cmd
		if msg.err == nil {
			m.c, m.key, m.lastInput = msg.c, msg.key, time.Now()
			load = m.loadCmd() // decrypt while the lock animates
		}
		if msg.phrase != "" {
			a.setMode(modePhrase)
			a.phrase = msg.phrase
			return load
		}
		if msg.err != nil {
			a.phase, a.msg = phaseFailed, errText(msg.err)
			for i, f := range a.fields { // jump to the first field that needs retyping
				if len(f.buf) == 0 {
					a.focus = i
					break
				}
			}
			return nil
		}
		a.phase, a.openedAt = phaseOpened, m.frame
		return load

	case tickMsg:
		if a.phase == phaseOpened && m.frame-a.openedAt >= openFrames {
			a.phase = phaseIdle
			m.st = stateVault
		}

	case tea.PasteMsg:
		if f := a.focused(); f != nil && !busy {
			f.buf = appendSecret(f.buf, msg.Content)
		}

	case tea.KeyPressMsg:
		if busy {
			return nil
		}
		if a.mode == modePhrase {
			if msg.String() == "enter" {
				a.phrase = ""
				if m.key != nil {
					m.st = stateVault
				} else {
					a.setMode(modeLogin)
				}
			}
			return nil
		}
		if a.phase == phaseFailed {
			a.phase, a.msg = phaseIdle, ""
		}
		n := len(a.fields) + len(a.links)
		switch msg.String() {
		case "tab", "down":
			a.focus = (a.focus + 1) % n
		case "shift+tab", "up":
			a.focus = (a.focus + n - 1) % n
		case "esc":
			if a.mode != modeLogin {
				a.setMode(modeLogin)
			} else if f := a.focused(); f != nil {
				f.wipe()
			}
		case "ctrl+n":
			a.setMode(modeRegister)
		case "ctrl+r":
			a.setMode(modeRecover)
		case "ctrl+o":
			if a.mode == modeLogin && a.email != "" {
				return m.logout()
			}
		case "enter":
			switch {
			case a.focus >= len(a.fields):
				return a.links[a.focus-len(a.fields)].do(m)
			case a.focus < len(a.fields)-1:
				a.focus++
			default:
				return m.submitAuth()
			}
		default:
			if f := a.focused(); f != nil {
				f.edit(msg)
			}
		}
	}
	return nil
}

func (m *model) submitAuth() tea.Cmd {
	a := &m.auth
	email, fields := a.email, a.fields
	if fields[0].label == "Email" {
		email, fields = strings.TrimSpace(string(fields[0].buf)), fields[1:]
	}
	if email == "" {
		return a.fail("Enter your email")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return a.fail("That doesn't look like an email address")
	}
	for _, f := range fields {
		if len(bytes.TrimSpace(f.buf)) == 0 {
			return a.fail("Fill in every field")
		}
	}
	if a.mode != modeLogin {
		pw, confirm := fields[len(fields)-2].buf, fields[len(fields)-1].buf
		if !bytes.Equal(pw, confirm) {
			return a.fail("Passwords don't match")
		}
		if utf8.RuneCount(pw) < 8 {
			return a.fail("Use at least 8 characters")
		}
	}

	// Hand the secret buffers to the command, which zeroes them when done.
	secrets := make([][]byte, len(fields))
	for i := range fields {
		secrets[i], fields[i].buf = fields[i].buf, nil
	}
	a.email, a.phase, a.msg = email, phaseWorking, ""

	server := m.server
	switch a.mode {
	case modeRegister:
		pw := secrets[0]
		return m.authCmd(email, pw, secrets, func() (string, error) {
			return vault.Register(server, email, pw)
		})
	case modeRecover:
		phrase, pw := secrets[0], secrets[1]
		return m.authCmd(email, pw, secrets, func() (string, error) {
			return "", vault.Recover(server, email, string(phrase), pw)
		})
	}
	return m.authCmd(email, secrets[0], secrets, nil)
}

// authCmd runs pre (register or recover) if given, then logs in with pw.
// It runs off the UI goroutine and zeroes every secret it was handed.
func (m *model) authCmd(email string, pw []byte, secrets [][]byte, pre func() (string, error)) tea.Cmd {
	server, onLogin := m.server, m.onLogin
	return func() tea.Msg {
		defer func() {
			for _, s := range secrets {
				clear(s)
			}
		}()
		var phrase string
		if pre != nil {
			p, err := pre()
			if err != nil {
				return authDoneMsg{err: err}
			}
			phrase = p
		}
		c, key, err := vault.Unlock(server, email, pw)
		if err != nil {
			return authDoneMsg{phrase: phrase, err: err}
		}
		if onLogin != nil {
			onLogin(email, c.Token)
		}
		return authDoneMsg{c: c, key: key, phrase: phrase}
	}
}

func (m *model) viewAuth() string {
	a, th := m.auth, m.th
	if a.mode == modePhrase {
		return m.viewPhrase()
	}
	w, h := m.bodySize()
	fw := min(44, w-4)

	title, sub, badge := "Welcome back", "Enter your master password to unlock your vault", "UNLOCK"
	switch {
	case a.mode == modeRegister:
		title, sub, badge = "Create your vault", "Pick a master password. It never leaves this device.", "REGISTER"
	case a.mode == modeRecover:
		title, sub, badge = "Recover your vault", "Use your 24-word recovery phrase to set a new master password.", "RECOVER"
	case a.lockedTitle != "":
		title, sub = a.lockedTitle, "Your key was cleared from memory. Nothing was written to disk."
	}

	art, lockC := lockClosed, th.Accent
	switch a.phase {
	case phaseFailed:
		lockC = th.Err
	case phaseOpened:
		art, lockC = lockOpen, th.Ok
	}

	var inputs []string
	for i := range a.fields {
		active := i == a.focus && a.phase != phaseWorking && a.phase != phaseOpened
		inputs = append(inputs, m.input(&a.fields[i], active, fw, active && a.phase == phaseFailed))
	}
	var status string
	switch a.phase {
	case phaseWorking:
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		status = fg(th.Accent).Render(spin) + fg(th.Muted).Render("deriving keys with Argon2id…") +
			"\n" + bounceBar(m.frame, fw, th.Accent, th.Border)
	case phaseFailed:
		status = fg(th.Err).Render(a.msg)
	case phaseOpened:
		status = fg(th.Ok).Render("✓ vault unlocked")
	}
	inputs = append(inputs, lipgloss.NewStyle().Width(fw).Height(2).Render(status))
	panel := strings.Join(inputs, "\n")

	links := make([]string, len(a.links))
	for i, l := range a.links {
		if a.focus == len(a.fields)+i {
			links[i] = fg(th.Accent).Bold(true).Underline(true).Render("› "+l.label) + " " + fg(th.Muted).Render(l.key)
		} else {
			links[i] = fg(th.Muted).Render("  "+l.label) + " " + fg(th.Border).Render(l.key)
		}
	}

	parts := []string{}
	if h >= 22 {
		parts = append(parts, fg(lockC).Render(strings.Join(art, "\n")), "")
	}
	parts = append(parts,
		fg(th.Fg).Bold(true).Render(title),
		fg(th.Muted).Render(sub),
		"",
		panel,
		strings.Join(links, "   "),
	)
	body := lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Center, parts...))

	right := fg(th.Muted).Render("vault locked")
	if a.email != "" {
		right = fg(th.Accent2).Render(a.email)
	}
	verb := map[authMode]string{modeLogin: "unlock", modeRegister: "create", modeRecover: "reset"}[a.mode]
	return m.chrome("", right, body, badge, "enter", verb, "tab", "next", "ctrl+c", "quit")
}

func (m *model) viewPhrase() string {
	th := m.th
	w, _ := m.bodySize()
	words := strings.Fields(m.auth.phrase)
	cols := 4
	if w < 70 {
		cols = 2
	}
	rows := (len(words) + cols - 1) / cols
	lines := make([]string, rows)
	for i, word := range words { // row-major, like the mockup: 01 02 03 04 / 05 ...
		lines[i/cols] += fg(th.Muted).Render(fmt.Sprintf("%02d ", i+1)) +
			fg(th.Fg).Render(fmt.Sprintf("%-10s", word)) + "  "
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.Border).
		Padding(0, 2).Render(strings.Join(lines, "\n"))

	body := lipgloss.JoinVertical(lipgloss.Left,
		fg(th.Fg).Bold(true).Render("Write down your recovery phrase"),
		fg(th.Warn).Render("Shown once. Anyone with these words can reset your master password."),
		"",
		box,
	)
	next := "open your vault"
	if m.key == nil {
		next = "log in"
	}
	return m.chrome(m.crumbs("account created"), fg(th.Muted).Render(m.auth.email), body,
		"PHRASE", "enter", "I've saved it, "+next, "ctrl+c", "quit")
}

// bounceBar is an indeterminate progress bar: a ▰ segment sliding back and forth.
func bounceBar(frame, width int, on, off color.Color) string {
	seg := max(width/4, 1)
	span := width - seg
	pos := 0
	if span > 0 {
		pos = frame % (2 * span)
		if pos > span {
			pos = 2*span - pos
		}
	}
	onS, offS := lipgloss.NewStyle().Foreground(on), lipgloss.NewStyle().Foreground(off)
	return offS.Render(strings.Repeat("▱", pos)) + onS.Render(strings.Repeat("▰", seg)) +
		offS.Render(strings.Repeat("▱", width-pos-seg))
}
