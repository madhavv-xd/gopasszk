package tui

import (
	"fmt"
	"image/color"
	"sort"
	"strings"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type listState struct {
	cursor, offset int
	filter         field
	filtering      bool
	recent         bool   // sort by last updated instead of name
	want           string // credential ID to select once the next load lands
	pageSize       int    // rows visible last render, for pgup/pgdn
}

// clamp keeps the cursor in range and, after a reload, moves it to l.want.
func (l *listState) clamp(m *model) {
	vis := m.visible()
	if l.want != "" {
		for i, idx := range vis {
			if m.entries[idx].ID == l.want {
				l.cursor = i
			}
		}
		l.want = ""
	}
	l.cursor = max(min(l.cursor, len(vis)-1), 0)
}

// visible lists indexes into m.entries that match the filter, in display order.
func (m *model) visible() []int {
	q := strings.ToLower(strings.TrimSpace(string(m.list.filter.buf)))
	var out []int
	for i, e := range m.entries {
		if q == "" || strings.Contains(strings.ToLower(e.SiteName), q) || strings.Contains(strings.ToLower(e.user), q) {
			out = append(out, i)
		}
	}
	if m.list.recent {
		sort.SliceStable(out, func(a, b int) bool {
			return m.entries[out[a]].UpdatedAt.After(m.entries[out[b]].UpdatedAt)
		})
	}
	return out
}

// issue is the most serious problem with e's password, as a sentence, a tag
// and a color. tag is "" when the password is healthy.
func (m *model) issue(e *entry) (text, tag string, c color.Color) {
	if n := m.breached[e.ID]; n > 0 {
		return fmt.Sprintf("Found in known breaches (%d times)", n), "breached", m.th.Err
	}
	if len(e.reused) > 0 {
		return "Reused on " + strings.Join(e.reused, ", "), "reused", m.th.Warn
	}
	if e.weakWhy != "" {
		return e.weakWhy, "weak", m.th.Warn
	}
	return "Healthy", "", m.th.Ok
}

func (m *model) openItem(back state) {
	m.itemBack = back
	m.hideReveal()
	m.st = stateItem
}

func (m *model) updateVault(msg tea.Msg) tea.Cmd {
	l := &m.list
	if p, ok := msg.(tea.PasteMsg); ok && l.filtering {
		l.filter.buf = appendSecret(l.filter.buf, p.Content)
		l.cursor, l.offset = 0, 0
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil
	}
	if l.filtering {
		switch k.String() {
		case "esc":
			l.filter.wipe()
			l.filtering = false
		case "enter", "down", "up", "tab":
			l.filtering = false
		default:
			if l.filter.edit(k) {
				l.cursor, l.offset = 0, 0
				m.hideReveal()
			}
		}
		return nil
	}

	n := len(m.visible())
	page := max(l.pageSize, 1)
	move := func(to int) {
		if to = max(min(to, n-1), 0); to != l.cursor {
			l.cursor = to
			m.hideReveal()
		}
	}
	switch k.String() {
	case "up", "k":
		move(l.cursor - 1)
	case "down", "j":
		move(l.cursor + 1)
	case "pgup", "ctrl+u":
		move(l.cursor - page)
	case "pgdown", "ctrl+d":
		move(l.cursor + page)
	case "home", "g":
		move(0)
	case "end", "G":
		move(n - 1)
	case "/", "ctrl+f":
		l.filtering = true
	case "esc":
		l.filter.wipe()
		l.clamp(m)
	case "s":
		l.recent = !l.recent
		l.cursor, l.offset = 0, 0
	case "a", "n":
		m.openEdit(nil)
	case "A":
		return m.openHealth()
	case "p":
		m.openPassword()
	case "r":
		m.loaded, m.loadErr = false, ""
		return m.loadCmd()
	case "ctrl+g":
		return m.genCopyCmd()
	}

	e := m.selected()
	if e == nil {
		return nil
	}
	switch k.String() {
	case "enter", "right", "l":
		m.openItem(stateVault)
	case "e":
		m.openEdit(e)
	case "d", "x", "delete":
		m.openDelete(e)
	case "c", "y":
		return m.copyCmd(*e, "Password")
	case "u":
		return m.copyCmd(*e, "Username")
	case "v":
		m.reveal(e)
	}
	return nil
}

func (m *model) viewVault() string {
	th := m.th
	w, h := m.bodySize()
	vis := m.visible()

	title := fg(th.Muted).Render(" · " + credentials(len(m.entries)))
	if len(m.list.filter.buf) > 0 {
		title += fg(th.Accent).Render(fmt.Sprintf(" · %d match", len(vis)))
	}
	if m.list.recent {
		title += fg(th.Muted).Render(" · recent first")
	}
	badge := "VAULT"
	hints := []string{"↑↓", "move", "enter", "open", "/", "search", "a", "add", "c", "copy", "?", "all keys"}
	if m.list.filtering {
		badge, hints = "SEARCH", []string{"type", "to search", "enter", "done", "esc", "clear"}
	}

	var body string
	switch {
	case m.loadErr != "":
		body = center(w, h, fg(th.Err).Render("Could not load your vault"), fg(th.Muted).Render(m.loadErr), "",
			m.hints("r", "retry", "L", "lock"))
	case !m.loaded:
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		body = center(w, h, fg(th.Accent).Render(spin)+fg(th.Muted).Render("decrypting your vault…"))
	case len(m.entries) == 0:
		body = center(w, h, fg(th.Fg).Bold(true).Render("Your vault is empty"),
			fg(th.Muted).Render("Press "+fg(th.Accent).Bold(true).Render("a")+" to add your first credential,"),
			fg(th.Muted).Render("or "+fg(th.Accent).Bold(true).Render("ctrl+g")+" to generate a password."))
		hints = []string{"a", "add", "ctrl+g", "generate", "?", "all keys", "q", "quit"}
	default:
		sel := m.selected()
		switch {
		case w >= 90 && sel != nil:
			body = lipgloss.JoinHorizontal(lipgloss.Top, m.viewList(vis, w-37, h), "  ", m.viewDetailPane(sel, 35, h))
		case h >= 24 && sel != nil: // narrow: stack the detail under the list
			body = lipgloss.JoinVertical(lipgloss.Left, m.viewList(vis, w, h-11), m.viewDetailPane(sel, w, 11))
		default:
			body = m.viewList(vis, w, h)
		}
	}
	return m.chrome(title, m.autoLockBar(), body, badge, hints...)
}

func center(w, h int, lines ...string) string {
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Center, lines...))
}

func (m *model) viewList(vis []int, w, h int) string {
	th, l := m.th, &m.list

	// One-line search with a rule under it.
	search := fg(th.Muted).Render("/ search " + credentials(len(m.entries)))
	if l.filtering || len(l.filter.buf) > 0 {
		search = fg(th.Accent).Bold(true).Render("/ ") + fg(th.Fg).Render(truncate(string(l.filter.buf), w-4))
		if l.filtering && (m.frame/6)%2 == 0 {
			search += lipgloss.NewStyle().Background(th.Accent).Render(" ")
		}
	}
	rule := th.Border
	if l.filtering {
		rule = th.Accent
	}
	rows := []string{search, fg(rule).Render(strings.Repeat("─", w))}

	n := max(h-3, 1) // rows that fit under the search line and above "↓ more"
	l.pageSize = n
	if l.cursor < l.offset {
		l.offset = l.cursor
	}
	if l.cursor >= l.offset+n {
		l.offset = l.cursor - n + 1
	}
	q := strings.ToLower(strings.TrimSpace(string(l.filter.buf)))
	if len(vis) == 0 {
		rows = append(rows, fg(th.Muted).Render(fmt.Sprintf("  nothing matches %q · esc to clear", q)))
	}
	for i := l.offset; i < min(len(vis), l.offset+n); i++ {
		rows = append(rows, m.listRow(&m.entries[vis[i]], i == l.cursor, w, q))
	}
	if more := len(vis) - (l.offset + n); more > 0 {
		rows = append(rows, fg(th.Muted).Render(fmt.Sprintf("  ↓ %d more", more)))
	}
	return strings.Join(rows, "\n")
}

func (m *model) listRow(e *entry, sel bool, w int, q string) string {
	th := m.th
	base := lipgloss.NewStyle()
	var avatarBg color.Color
	if sel {
		base, avatarBg = base.Background(th.Sel), th.Sel
	}
	cell := func(s string, width int, c color.Color, bold bool) string {
		return base.Foreground(c).Bold(bold).Width(width).Render(truncate(s, width-1))
	}

	const fixed = 2 + 4 + 11 + 5 // marker, avatar, tag, age
	siteW := max((w-fixed)*45/100, 10)
	userW := max(w-fixed-siteW, 0)

	marker := cell("", 2, th.Accent, true)
	if sel {
		marker = cell("›", 2, th.Accent, true)
	}

	// Site, with the search match highlighted.
	site := truncate(e.SiteName, siteW-1)
	var siteS string
	if i := strings.Index(strings.ToLower(site), q); q != "" && i >= 0 && i+len(q) <= len(site) {
		siteS = base.Foreground(th.Fg).Bold(true).Render(site[:i]) +
			base.Foreground(th.Accent).Bold(true).Underline(true).Render(site[i:i+len(q)]) +
			base.Foreground(th.Fg).Bold(true).Render(site[i+len(q):])
	} else {
		siteS = base.Foreground(th.Fg).Bold(true).Render(site)
	}
	siteS += base.Render(strings.Repeat(" ", max(siteW-lipgloss.Width(siteS), 0)))

	var tagS string
	if _, t, c := m.issue(e); t != "" {
		tagS = m.tag(t, c)
	}
	tagS += base.Render(strings.Repeat(" ", max(11-lipgloss.Width(tagS), 0)))

	age := base.Foreground(th.Muted).Width(5).Align(lipgloss.Right).Render(ago(e.UpdatedAt))
	return marker + m.avatar(e.SiteName, avatarBg) + siteS + cell(e.user, userW, th.Accent2, false) + tagS + age
}

// viewDetailPane is the selected credential beside (or under) the list,
// separated by a thin rule rather than a box.
func (m *model) viewDetailPane(e *entry, w, h int) string {
	th := m.th
	inner := w - 3
	text, _, c := m.issue(e)
	pw := fg(th.Muted).Render(strings.Repeat("•", 14))
	if m.revealed == e.ID {
		pw = m.colorize(truncate(m.revealPw, inner))
	}
	content := lipgloss.JoinVertical(lipgloss.Left,
		fg(th.Fg).Bold(true).Render(truncate(e.SiteName, inner)),
		fg(th.Accent2).Render(truncate(e.user, inner)),
		"",
		m.label("Password"), pw,
		"",
		m.label("Health"), fg(c).Width(inner).Render(text),
		"",
		m.label("Strength"), m.strengthBar(e.score),
		"",
		m.hints("c", "copy", "v", "reveal", "e", "edit"),
	)
	return lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(th.Border).PaddingLeft(2).Width(w).Height(h).MaxHeight(h).Render(content)
}
