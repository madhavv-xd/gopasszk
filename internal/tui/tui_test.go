package tui

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/madhavv-xd/gopasszk/internal/client"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

func press(m *model, keys ...string) tea.Cmd {
	var cmd tea.Cmd
	for _, s := range keys {
		var k tea.KeyPressMsg
		switch s {
		case "enter":
			k = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "tab":
			k = tea.KeyPressMsg{Code: tea.KeyTab}
		case "esc":
			k = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "up":
			k = tea.KeyPressMsg{Code: tea.KeyUp}
		case "down":
			k = tea.KeyPressMsg{Code: tea.KeyDown}
		case "left":
			k = tea.KeyPressMsg{Code: tea.KeyLeft}
		case "right":
			k = tea.KeyPressMsg{Code: tea.KeyRight}
		case "ctrl+c", "ctrl+s", "ctrl+l", "ctrl+o":
			k = tea.KeyPressMsg{Code: rune(s[5]), Mod: tea.ModCtrl}
		default:
			k = tea.KeyPressMsg{Code: rune(s[0]), Text: s}
		}
		_, cmd = m.Update(k)
	}
	return cmd
}

func typeText(m *model, s string) {
	for _, c := range s {
		press(m, string(c))
	}
}

func ticks(m *model, n int) {
	for range n {
		m.Update(tickMsg(time.Now()))
	}
}

// unlocked returns a model sitting on the vault list with sample entries.
func unlocked(entries ...entry) *model {
	m := newModel("http://unused", "a@b.co")
	m.st, m.key, m.c, m.lastInput = stateVault, bytes.Repeat([]byte{1}, 32), &client.Client{}, time.Now()
	m.Update(loadedMsg{entries: entries})
	return m
}

func sample() []entry {
	now := time.Now()
	mk := func(id, site, user string) entry {
		ct, _ := vault.EncryptField(bytes.Repeat([]byte{1}, 32), "pw-"+id) // the key unlocked() uses
		return entry{Credential: client.Credential{ID: id + "-0000-0000", SiteName: site, PasswordCiphertext: ct,
			UpdatedAt: now, CreatedAt: now}, user: user, score: 4}
	}
	gh, gl, ig := mk("1", "github", "me@x.io"), mk("2", "gitlab", "me@x.io"), mk("3", "instagram", "handle")
	gh.reused, gl.reused = []string{"gitlab"}, []string{"github"}
	ig.weakWhy, ig.score = "Under 12 characters", 1
	return []entry{gh, gl, ig, mk("4", "neon", "me@x.io")}
}

func TestSplashToLoginToVaultAndLock(t *testing.T) {
	m := newModel("http://unused", "a@b.co")
	m.Update(healthMsg{ok: false}) // server down: boot still continues
	ticks(m, 2*len(logo))
	press(m, "enter")
	ticks(m, (len(bootSteps)+2)*bootStepFrames)
	if m.st != stateAuth || len(m.auth.fields) != 1 {
		t.Fatalf("known email: want login with only a password field, got state %d, %d fields", m.st, len(m.auth.fields))
	}

	typeText(m, "hunter22")
	if press(m, "enter") == nil || m.auth.fields[0].buf != nil || m.auth.phase != phaseWorking {
		t.Fatal("enter should hand the password to a cmd and drop it from the model")
	}
	m.Update(authDoneMsg{err: vault.ErrWrongPassword})
	if m.auth.msg != "Wrong master password" || m.auth.phase != phaseFailed {
		t.Fatalf("got %q", m.auth.msg)
	}
	m.Update(authDoneMsg{err: &client.APIError{Status: 500, Message: "boom"}})
	if !strings.Contains(m.auth.msg, "500") {
		t.Fatalf("non-401 errors should show as-is, got %q", m.auth.msg)
	}

	key := []byte{1, 2, 3, 4}
	if _, cmd := m.Update(authDoneMsg{c: &client.Client{}, key: key}); cmd == nil {
		t.Fatal("unlock should start loading the vault")
	}
	ticks(m, openFrames)
	if m.st != stateVault {
		t.Fatalf("want vault, got state %d", m.st)
	}
	press(m, "L")
	if m.st != stateAuth || m.key != nil || !bytes.Equal(key, make([]byte, 4)) || m.auth.lockedTitle == "" {
		t.Fatalf("lock must zero the key and show the locked screen: %v", key)
	}
	if m.auth.email != "a@b.co" {
		t.Fatal("lock should keep the email")
	}
}

func TestLinksAndValidation(t *testing.T) {
	m := newModel("http://unused", "")
	m.st = stateAuth
	press(m, "tab", "tab", "enter") // email -> password -> "create account"
	if m.auth.mode != modeRegister {
		t.Fatalf("want register mode, got %d", m.auth.mode)
	}
	typeText(m, "not-an-email")
	press(m, "tab")
	typeText(m, "longenough")
	press(m, "tab")
	typeText(m, "different!")
	if press(m, "enter") != nil || m.auth.msg != "That doesn't look like an email address" {
		t.Fatalf("got %q", m.auth.msg)
	}
	m.auth.fields[0].set("a@b.co")
	if press(m, "enter") != nil || m.auth.msg != "Passwords don't match" {
		t.Fatalf("got %q", m.auth.msg)
	}
	press(m, "esc")
	if m.auth.mode != modeLogin || m.auth.email != "a@b.co" {
		t.Fatal("esc should go back to login and carry the email")
	}
}

func TestRegisterShowsPhraseOnce(t *testing.T) {
	m := newModel("http://unused", "a@b.co")
	m.st = stateAuth
	m.Update(authDoneMsg{c: &client.Client{}, key: []byte{1}, phrase: "w1 w2 w3"})
	if m.auth.mode != modePhrase || !strings.Contains(m.View().Content, "w2") {
		t.Fatal("phrase screen should show the words")
	}
	press(m, "enter")
	if m.st != stateVault || m.auth.phrase != "" {
		t.Fatal("enter should drop the phrase and open the vault")
	}
}

func TestAutoLockAndQuitZeroKey(t *testing.T) {
	m := unlocked(sample()...)
	key := m.key
	m.lastInput = time.Now().Add(-autoLock - time.Second)
	ticks(m, 1)
	if m.st != stateAuth || !bytes.Equal(key, make([]byte, 32)) || m.entries != nil {
		t.Fatal("idle auto-lock must zero the key and drop decrypted data")
	}

	key = []byte{7}
	m.key = key
	typeText(m, "pw")
	pw := m.auth.fields[0].buf
	press(m, "ctrl+c")
	if key[0] != 0 || !bytes.Equal(pw, []byte{0, 0}) {
		t.Fatal("ctrl+c must zero key and password")
	}
}

func TestFilterOpenAndDelete(t *testing.T) {
	m := unlocked(sample()...)
	press(m, "/")
	typeText(m, "git")
	if n := len(m.visible()); n != 2 {
		t.Fatalf("filter git: want 2 matches, got %d", n)
	}
	press(m, "enter", "down", "enter") // leave filter, move to gitlab, open
	if m.st != stateItem || m.selected().SiteName != "gitlab" {
		t.Fatalf("want gitlab item, got state %d", m.st)
	}
	press(m, "d")
	typeText(m, "gitla")
	if press(m, "enter") != nil || m.del.err == "" {
		t.Fatal("a partial name must not delete")
	}
	typeText(m, "b")
	if press(m, "enter") == nil {
		t.Fatal("matching name should send the delete")
	}
	m.Update(deletedMsg{id: m.del.id, site: "gitlab"})
	if m.st != stateVault || len(m.entries) != 3 || m.toast == nil {
		t.Fatalf("delete should drop the entry and toast, got %d entries", len(m.entries))
	}
}

func TestAddGeneratesBlankPassword(t *testing.T) {
	m := unlocked()
	press(m, "a")
	if m.st != stateEdit {
		t.Fatal("a should open the add form")
	}
	typeText(m, "example")
	if press(m, "enter") != nil || m.edit.focus != 1 {
		t.Fatal("enter on an early field should move on, not save a half-filled form")
	}
	press(m, "right", "right")
	if press(m, "ctrl+s") == nil {
		t.Fatal("ctrl+s should save from any field")
	}
	if n := len(m.edit.fields[2].buf); n != 22 {
		t.Fatalf("blank password should be generated at the chosen length, got %d", n)
	}
}

func TestBackGoesWhereYouCameFrom(t *testing.T) {
	m := unlocked(sample()...)
	press(m, "d", "esc")
	if m.st != stateVault {
		t.Fatalf("delete opened from the list should return to it, got %d", m.st)
	}
	press(m, "enter", "e", "esc")
	if m.st != stateItem {
		t.Fatalf("edit opened from an item should return to it, got %d", m.st)
	}
	press(m, "esc", "s")                               // sort by recent so visible order differs from entries order
	m.entries[2].UpdatedAt = time.Now().Add(time.Hour) // instagram is now first
	m.Update(auditMsg{})
	m.openHealth()
	press(m, "down", "down", "down", "enter") // last issue: instagram (weak)
	if m.st != stateItem || m.selected().SiteName != "instagram" {
		t.Fatalf("health should open the chosen credential, got %q", m.selected().SiteName)
	}
	press(m, "esc")
	if m.st != stateHealth {
		t.Fatalf("esc from an item opened in health should return there, got %d", m.st)
	}
}

func TestLockAnywhereAndLogout(t *testing.T) {
	m := unlocked(sample()...)
	press(m, "a")
	typeText(m, "half typed")
	press(m, "ctrl+l")
	if m.st != stateAuth || m.key != nil || m.edit.fields[0].buf != nil {
		t.Fatal("ctrl+l should lock even while typing, and wipe the form")
	}

	loggedOut := false
	m = unlocked(sample()...)
	m.onLogout = func() { loggedOut = true }
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'O', Text: "O"})
	for _, msg := range runBatch(cmd) {
		_ = msg
	}
	if !loggedOut || m.auth.email != "" || m.key != nil || len(m.auth.fields) != 2 {
		t.Fatal("O should log out: forget the session, clear the email, show email + password")
	}
}

// runBatch executes a command and any batch inside it, returning the messages.
func runBatch(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if b, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range b {
			out = append(out, runBatch(c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func TestRevealAutoHidesAndEmptyUsername(t *testing.T) {
	e := sample()[0]
	ct, _ := vault.EncryptField(bytes.Repeat([]byte{1}, 32), "hunter2")
	e.PasswordCiphertext, e.user = ct, ""
	m := unlocked(e)
	press(m, "v")
	if m.revealPw != "hunter2" {
		t.Fatalf("v should reveal, got %q", m.revealPw)
	}
	m.revealAt = time.Now().Add(-revealTimeout - time.Second)
	ticks(m, 1)
	if m.revealed != "" || m.revealPw != "" {
		t.Fatal("a revealed password should hide itself")
	}
	if press(m, "u") != nil || m.toast == nil || !m.toast.bad {
		t.Fatal("copying an empty username should warn, not copy")
	}
}

func TestSplashSkipsOnAnyKey(t *testing.T) {
	m := newModel("http://unused", "")
	press(m, "x")
	if m.st != stateAuth {
		t.Fatal("any key should skip the splash")
	}
	m = newModel("http://unused", "")
	m.Update(healthMsg{ok: true})
	ticks(m, (len(bootSteps)+2)*bootStepFrames)
	if m.st != stateAuth {
		t.Fatal("the splash should continue on its own")
	}
}

func TestHealthRanksIssues(t *testing.T) {
	m := unlocked(sample()...)
	m.Update(auditMsg{breached: map[string]int{"4-0000-0000": 3}})
	issues := m.issues()
	if len(issues) != 4 || m.entries[issues[0]].SiteName != "neon" {
		t.Fatalf("breached should rank first, got %v", issues)
	}
	if _, tag, _ := m.issue(&m.entries[issues[3]]); tag != "weak" {
		t.Fatalf("weak should rank last, got %q", tag)
	}
}

func TestLoadDecryptsAndFindsReuse(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	enc := func(s string) string { ct, _ := vault.EncryptField(key, s); return ct }
	creds := []client.Credential{
		{ID: "1", SiteName: "b-site", UsernameCiphertext: enc("bob"), PasswordCiphertext: enc("same-Pass-123!")},
		{ID: "2", SiteName: "a-site", UsernameCiphertext: enc("amy"), PasswordCiphertext: enc("same-Pass-123!")},
		{ID: "3", SiteName: "c-site", UsernameCiphertext: enc("cat"), PasswordCiphertext: enc("short")},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"credentials": creds})
	}))
	defer srv.Close()

	m := newModel(srv.URL, "a@b.co")
	m.c, m.key = client.New(srv.URL), key
	msg := m.loadCmd()().(loadedMsg)
	if msg.err != nil {
		t.Fatal(msg.err)
	}
	e := msg.entries
	if e[0].SiteName != "a-site" || e[0].user != "amy" {
		t.Fatalf("want sorted and decrypted, got %+v", e[0])
	}
	if len(e[0].reused) != 1 || e[0].reused[0] != "b-site" || e[2].weakWhy == "" {
		t.Fatalf("reuse/weak detection wrong: %+v", e)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("loadCmd must zero its own copy, not the model's key")
	}
}

func TestAuthCmdZeroesSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"down"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	m := newModel(srv.URL, "a@b.co")
	pw, extra := []byte("secret"), []byte("other")
	msg := m.authCmd("a@b.co", pw, [][]byte{pw, extra}, nil)().(authDoneMsg)
	if msg.err == nil || errText(msg.err) == "Wrong master password" {
		t.Fatalf("server errors should surface as-is, got %v", msg.err)
	}
	if !bytes.Equal(pw, make([]byte, len(pw))) || !bytes.Equal(extra, make([]byte, len(extra))) {
		t.Fatal("authCmd must zero every secret")
	}
}

func TestNoDirectAESImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		ast, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range ast.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); p == "crypto/aes" || p == "crypto/cipher" {
				t.Errorf("%s imports %s; go through internal/vault", f, p)
			}
		}
	}
}

func TestEveryScreenRendersAtAnySize(t *testing.T) {
	for _, size := range [][2]int{{40, 16}, {80, 24}, {140, 45}} {
		for _, st := range []state{stateSplash, stateAuth, stateVault, stateItem, stateEdit, stateHealth, stateDelete, statePassword} {
			for _, help := range []bool{false, true} {
				m := unlocked(sample()...)
				m.w, m.h = size[0], size[1]
				m.openEdit(&m.entries[0])
				m.openDelete(&m.entries[0])
				m.openPassword()
				m.st, m.help = st, help
				if m.View().Content == "" {
					t.Errorf("empty view: state %d size %v", st, size)
				}
			}
		}
	}
}
