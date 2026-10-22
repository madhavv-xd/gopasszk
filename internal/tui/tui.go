// Package tui is the full-screen terminal UI for gopass.
//
// Security: the vault key, master password and decrypted fields live only in
// this process's memory. wipe() zeroes the key and every input buffer on lock
// and quit; commands that need the key get a copy they zero when done. All
// crypto goes through internal/vault; this package must not import
// crypto/aes or crypto/cipher.
package tui

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/atotto/clipboard"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/madhavv-xd/gopasszk/internal/audit"
	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/pwgn"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

type state int

const (
	stateSplash state = iota
	stateAuth
	stateVault
	stateItem
	stateEdit
	stateHealth
	stateDelete
	statePassword
)

const (
	frameRate     = 80 * time.Millisecond
	autoLock      = 5 * time.Minute
	clipTimeout   = 30 * time.Second
	revealTimeout = 20 * time.Second
	healthEvery   = 15 * time.Second
)

// entry is one credential with its username decrypted. Passwords are not
// kept: they're decrypted on demand for copy, reveal and edit.
type entry struct {
	client.Credential
	user    string
	score   int      // password strength 0-4
	weakWhy string   // "" unless audit.IsWeak
	reused  []string // other sites sharing this password
}

type toast struct {
	title, sub string
	bad        bool
	at         time.Time
	dur        time.Duration
}

type (
	tickMsg      time.Time
	healthMsg    struct{ ok bool }
	healthDueMsg struct{}
	loadedMsg    struct {
		entries []entry
		err     error
	}
	copiedMsg struct {
		what string
		hash [32]byte
		err  error
	}
	clipClearMsg struct{ hash [32]byte }
)

type model struct {
	st       state
	themeIdx int
	th       Theme
	w, h     int
	frame    int
	server   string
	online   bool
	checked  bool // at least one health check came back
	help     bool

	splash splashState
	auth   authState

	// onLogin persists the session (email + JWT) after a successful login;
	// onLogout forgets it.
	onLogin  func(email, token string)
	onLogout func()

	back     state // where esc returns to from edit, delete and password
	itemBack state // where esc returns to from the item screen

	// Set only while unlocked; wipe() clears them.
	c         *client.Client
	key       []byte
	lastInput time.Time
	entries   []entry
	loaded    bool
	loadErr   string
	breached  map[string]int // credential ID -> breach count, after an audit
	revealed  string         // ID of the credential whose password is shown
	revealPw  string
	revealAt  time.Time

	list   listState
	edit   editState
	health healthState
	del    deleteState
	pw     passwordState

	toast     *toast
	clipHash  [32]byte // SHA-256 of what we last copied; zero when nothing
	clipUntil time.Time
}

// Run starts the TUI. email prefills the login form and may be empty.
// onLogin, if non-nil, is called after every successful login, and onLogout
// when the user logs out.
func Run(server, email string, onLogin func(email, token string), onLogout func()) error {
	m := newModel(server, email)
	m.onLogin, m.onLogout = onLogin, onLogout
	final, err := tea.NewProgram(m).Run()
	if fm, ok := final.(*model); ok {
		fm.wipe()
		if fm.clipHash != ([32]byte{}) {
			clearClipboard(fm.clipHash)
		}
	}
	return err
}

func newModel(server, email string) *model {
	i := themeFromEnv()
	return &model{st: stateSplash, themeIdx: i, th: themes[i], w: 100, h: 30,
		server: server, auth: newAuth(email)}
}

func (m *model) Init() tea.Cmd { return tea.Batch(tick(), checkHealth(m.server)) }

func tick() tea.Cmd {
	return tea.Tick(frameRate, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func checkHealth(server string) tea.Cmd {
	return func() tea.Msg {
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(server + "/health")
		if err != nil {
			return healthMsg{false}
		}
		resp.Body.Close()
		return healthMsg{resp.StatusCode == http.StatusOK}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.InterruptMsg:
		return m, m.quit()
	case tickMsg:
		m.frame++
		var cmd tea.Cmd
		if m.key != nil && time.Since(m.lastInput) > autoLock {
			cmd = m.lock("Locked after 5 minutes of inactivity")
		}
		if m.toast != nil && time.Since(m.toast.at) > m.toast.dur {
			m.toast = nil
		}
		if m.revealed != "" && time.Since(m.revealAt) > revealTimeout {
			m.hideReveal()
		}
		return m, tea.Batch(cmd, m.route(msg), tick())
	case healthMsg:
		m.online, m.checked = msg.ok, true
		return m, tea.Tick(healthEvery, func(time.Time) tea.Msg { return healthDueMsg{} })
	case healthDueMsg:
		return m, checkHealth(m.server)
	case clipClearMsg:
		if msg.hash == m.clipHash {
			m.clipHash = [32]byte{}
			return m, func() tea.Msg { clearClipboard(msg.hash); return nil }
		}
		return m, nil
	case tea.KeyPressMsg:
		m.lastInput = time.Now()
		if cmd, done := m.globalKey(msg); done {
			return m, cmd
		}
	}

	// Results that arrive after a lock belong to a session that's gone.
	if m.key == nil {
		switch msg.(type) {
		case loadedMsg, copiedMsg, savedMsg, deletedMsg, auditMsg, pwChangedMsg:
			return m, nil
		}
	}
	switch msg := msg.(type) {
	case loadedMsg:
		if msg.err != nil {
			m.loadErr = errText(msg.err)
			return m, m.fail(msg.err)
		}
		m.entries, m.loaded, m.loadErr = msg.entries, true, ""
		m.list.clamp(m)
		return m, nil
	case auditMsg: // handled here so leaving the health screen mid-audit keeps the result
		m.health.running, m.health.done, m.health.failed = false, true, msg.failed
		m.breached = msg.breached
		return m, nil
	case copiedMsg:
		if msg.err != nil {
			return m, m.fail(msg.err)
		}
		m.clipHash, m.clipUntil = msg.hash, time.Now().Add(clipTimeout)
		m.notify(msg.what+" copied", "clipboard clears in 30s", false, 2500*time.Millisecond)
		return m, tea.Tick(clipTimeout, func(time.Time) tea.Msg { return clipClearMsg{msg.hash} })
	}
	return m, m.route(msg)
}

// route hands a message to the current screen.
func (m *model) route(msg tea.Msg) tea.Cmd {
	switch m.st {
	case stateSplash:
		return m.updateSplash(msg)
	case stateAuth:
		return m.updateAuth(msg)
	case stateVault:
		return m.updateVault(msg)
	case stateItem:
		return m.updateItem(msg)
	case stateEdit:
		return m.updateEdit(msg)
	case stateHealth:
		return m.updateHealth(msg)
	case stateDelete:
		return m.updateDelete(msg)
	case statePassword:
		return m.updatePassword(msg)
	}
	return nil
}

// typing reports whether keys go to a text input, so letters aren't shortcuts.
func (m *model) typing() bool {
	switch m.st {
	case stateAuth, stateEdit, stateDelete, statePassword:
		return true
	case stateVault:
		return m.list.filtering
	}
	return false
}

// globalKey handles keys that work on every screen. done means the key was used.
func (m *model) globalKey(k tea.KeyPressMsg) (tea.Cmd, bool) {
	key := k.String()
	if key == "ctrl+c" {
		return m.quit(), true
	}
	if m.help {
		if key == "?" || key == "esc" || key == "q" {
			m.help = false
		}
		return nil, true
	}
	if key == "ctrl+l" && m.key != nil { // lock works even while typing
		return m.lock("Vault locked"), true
	}
	if m.typing() || m.st == stateSplash {
		return nil, false
	}
	switch key {
	case "?":
		m.help = true
	case "T":
		m.themeIdx = (m.themeIdx + 1) % len(themes)
		m.th = themes[m.themeIdx]
		m.notify("Theme: "+m.th.Name, "set GOPASS_THEME to keep it", false, 2*time.Second)
	case "L":
		return m.lock("Vault locked"), true
	case "O":
		return m.logout(), true
	case "q":
		return m.quit(), true
	default:
		return nil, false
	}
	return nil, true
}

func (m *model) View() tea.View {
	var body string
	switch m.st {
	case stateSplash:
		body = m.viewSplash()
	case stateAuth:
		body = m.viewAuth()
	case stateVault:
		body = m.viewVault()
	case stateItem:
		body = m.viewItem()
	case stateEdit:
		body = m.viewEdit()
	case stateHealth:
		body = m.viewHealth()
	case stateDelete:
		body = m.viewDelete()
	case statePassword:
		body = m.viewPassword()
	}
	if m.help {
		body = m.viewHelp()
	}
	v := tea.NewView(lipgloss.NewStyle().MaxWidth(m.w).MaxHeight(m.h).Render(body))
	v.AltScreen = true
	v.WindowTitle = "gopass"
	v.BackgroundColor = m.th.Bg
	v.ForegroundColor = m.th.Fg
	return v
}

// wipe zeroes the key and every input buffer and forgets decrypted data.
func (m *model) wipe() {
	clear(m.key)
	m.key, m.c = nil, nil
	m.entries, m.loaded, m.loadErr, m.breached = nil, false, "", nil
	m.revealed, m.revealPw = "", ""
	m.auth.wipe()
	m.list.filter.wipe()
	m.edit.wipe()
	m.del.input.wipe()
	m.pw.wipe()
	m.help = false
}

// lock wipes the session and returns to the unlock screen. It also clears
// the clipboard if it still holds something we copied.
func (m *model) lock(title string) tea.Cmd {
	m.wipe()
	m.st = stateAuth
	m.auth.setMode(modeLogin)
	m.auth.lockedTitle = title
	m.list = listState{}
	m.health = healthState{}
	if h := m.clipHash; h != ([32]byte{}) {
		m.clipHash = [32]byte{}
		return func() tea.Msg { clearClipboard(h); return nil }
	}
	return nil
}

// logout locks, forgets the account on this device (the saved session file)
// and returns to an empty login form.
func (m *model) logout() tea.Cmd {
	cmd := m.lock("")
	m.auth.email = ""
	m.auth.setMode(modeLogin)
	m.notify("Logged out", "saved session removed from this device", false, 3*time.Second)
	onLogout := m.onLogout
	return tea.Batch(cmd, func() tea.Msg {
		if onLogout != nil {
			onLogout()
		}
		return nil
	})
}

func (m *model) quit() tea.Cmd {
	m.wipe()
	return tea.Quit
}

func (m *model) notify(title, sub string, bad bool, dur time.Duration) {
	m.toast = &toast{title: title, sub: sub, bad: bad, at: time.Now(), dur: dur}
}

// fail reports an error from a vault operation. A 401 here means the session
// token expired, so the vault locks; anything else shows as-is.
func (m *model) fail(err error) tea.Cmd {
	var apiErr *client.APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		return m.lock("Session expired")
	}
	m.notify("Something went wrong", err.Error(), true, 5*time.Second)
	return nil
}

// errText maps auth errors to what the user sees: a 401 means a wrong master
// password; anything else (server down, 500) is shown as-is.
func errText(err error) string {
	var apiErr *client.APIError
	if errors.Is(err, vault.ErrWrongPassword) || (errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized) {
		return "Wrong master password"
	}
	return err.Error()
}

// loadCmd fetches and decrypts the vault. Plaintext passwords are only used
// here to score strength and spot reuse, then dropped.
func (m *model) loadCmd() tea.Cmd {
	c, key := m.c, bytes.Clone(m.key)
	return func() tea.Msg {
		defer clear(key)
		creds, err := c.ListCredentials()
		if err != nil {
			return loadedMsg{err: err}
		}
		entries := make([]entry, len(creds))
		same := map[[32]byte][]int{}
		for i, cr := range creds {
			e := entry{Credential: cr}
			e.user, err = vault.DecryptField(key, cr.UsernameCiphertext)
			if err != nil {
				return loadedMsg{err: errors.New("could not decrypt " + cr.SiteName)}
			}
			pass, err := vault.DecryptField(key, cr.PasswordCiphertext)
			if err != nil {
				return loadedMsg{err: errors.New("could not decrypt " + cr.SiteName)}
			}
			e.score = strength([]byte(pass))
			if audit.IsWeak(pass) {
				e.weakWhy = "Missing character types"
				if len(pass) < 12 {
					e.weakWhy = "Under 12 characters"
				}
			}
			h := sha256.Sum256([]byte(pass))
			same[h] = append(same[h], i)
			entries[i] = e
		}
		for _, group := range same {
			for _, i := range group {
				for _, j := range group {
					if i != j {
						entries[i].reused = append(entries[i].reused, entries[j].SiteName)
					}
				}
			}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].SiteName) < strings.ToLower(entries[j].SiteName)
		})
		return loadedMsg{entries: entries}
	}
}

// copyCmd puts a password or username on the clipboard. Only a hash of it is
// kept, to check later that the clipboard still holds our copy before clearing.
func (m *model) copyCmd(e entry, what string) tea.Cmd {
	if what == "Username" && e.user == "" {
		m.notify("No username saved", "nothing was copied", true, 2500*time.Millisecond)
		return nil
	}
	key := bytes.Clone(m.key)
	return func() tea.Msg {
		defer clear(key)
		s := e.user
		if what == "Password" {
			var err error
			if s, err = vault.DecryptField(key, e.PasswordCiphertext); err != nil {
				return copiedMsg{err: err}
			}
		}
		if err := clipboard.WriteAll(s); err != nil {
			return copiedMsg{err: err}
		}
		return copiedMsg{what: what, hash: sha256.Sum256([]byte(s))}
	}
}

// genCopyCmd generates a 20-character password and copies it without saving it.
func (m *model) genCopyCmd() tea.Cmd {
	return func() tea.Msg {
		pw, err := pwgn.Generate(20)
		if err != nil {
			return copiedMsg{err: err}
		}
		if err := clipboard.WriteAll(pw); err != nil {
			return copiedMsg{err: err}
		}
		return copiedMsg{what: "New password", hash: sha256.Sum256([]byte(pw))}
	}
}

// clearClipboard empties the clipboard if it still holds what we copied.
func clearClipboard(hash [32]byte) {
	if cur, err := clipboard.ReadAll(); err == nil && sha256.Sum256([]byte(cur)) == hash {
		_ = clipboard.WriteAll("")
	}
}

// selected returns the entry under the list cursor, or nil.
func (m *model) selected() *entry {
	vis := m.visible()
	if m.list.cursor < len(vis) {
		return &m.entries[vis[m.list.cursor]]
	}
	return nil
}

// reveal toggles showing e's password.
func (m *model) reveal(e *entry) {
	if m.revealed == e.ID {
		m.revealed, m.revealPw = "", ""
		return
	}
	pw, err := vault.DecryptField(m.key, e.PasswordCiphertext)
	if err != nil {
		m.notify("Could not decrypt", err.Error(), true, 4*time.Second)
		return
	}
	m.revealed, m.revealPw, m.revealAt = e.ID, pw, time.Now()
}

func (m *model) hideReveal() { m.revealed, m.revealPw = "", "" }
