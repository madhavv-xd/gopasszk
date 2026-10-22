package tui

import (
	"bytes"
	"fmt"
	"image/color"
	"math"
	"sort"
	"strings"
	"sync"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/madhavv-xd/gopasszk/internal/audit"
	"github.com/madhavv-xd/gopasszk/internal/vault"
)

type healthState struct {
	running bool
	done    bool // an audit finished this session
	failed  int  // breach lookups that errored
	cursor  int
}

type auditMsg struct {
	breached map[string]int
	failed   int
}

func (m *model) openHealth() tea.Cmd {
	m.st = stateHealth
	m.health.cursor = 0
	if !m.health.done && !m.health.running {
		return m.auditCmd()
	}
	return nil
}

// auditCmd checks every password against Have I Been Pwned. Each lookup
// sends only the first 5 hex chars of the password's SHA-1 (k-anonymity).
func (m *model) auditCmd() tea.Cmd {
	m.health.running = true
	key := bytes.Clone(m.key)
	type item struct{ id, ct string }
	items := make([]item, len(m.entries))
	for i, e := range m.entries {
		items[i] = item{e.ID, e.PasswordCiphertext}
	}
	return func() tea.Msg {
		defer clear(key)
		var (
			mu     sync.Mutex
			wg     sync.WaitGroup
			sem    = make(chan struct{}, 6)
			result = map[string]int{}
			failed int
		)
		for _, it := range items {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				n := 0
				pass, err := vault.DecryptField(key, it.ct)
				if err == nil {
					n, err = audit.PwnedCount(pass)
				}
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failed++
				} else {
					result[it.id] = n
				}
			}()
		}
		wg.Wait()
		return auditMsg{result, failed}
	}
}

// issues lists entries needing attention, most serious first.
func (m *model) issues() []int {
	rank := map[string]int{"breached": 0, "reused": 1, "weak": 2}
	var out []int
	for i := range m.entries {
		if _, t, _ := m.issue(&m.entries[i]); t != "" {
			out = append(out, i)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		_, ta, _ := m.issue(&m.entries[out[a]])
		_, tb, _ := m.issue(&m.entries[out[b]])
		return rank[ta] < rank[tb]
	})
	return out
}

func (m *model) updateHealth(msg tea.Msg) tea.Cmd {
	hs := &m.health
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		issues := m.issues()
		switch msg.String() {
		case "up", "k":
			hs.cursor = max(hs.cursor-1, 0)
		case "down", "j":
			hs.cursor = min(hs.cursor+1, max(len(issues)-1, 0))
		case "r":
			if !hs.running {
				return m.auditCmd()
			}
		case "esc", "backspace":
			m.st = stateVault
		case "enter":
			if hs.cursor < len(issues) {
				m.list.filter.wipe()
				m.list.want = m.entries[issues[hs.cursor]].ID
				m.list.clamp(m) // cursor indexes the visible order, which sorting can change
				m.openItem(stateHealth)
			}
		}
	}
	return nil
}

func (m *model) viewHealth() string {
	th, hs := m.th, m.health
	w, _ := m.bodySize()
	total := len(m.entries)
	var reused, weak, breached int
	for i := range m.entries {
		e := &m.entries[i]
		if len(e.reused) > 0 {
			reused++
		}
		if e.weakWhy != "" {
			weak++
		}
		if m.breached[e.ID] > 0 {
			breached++
		}
	}
	issues := m.issues()
	healthy := total - len(issues)
	score := 100
	if total > 0 {
		score = healthy * 100 / total
	}

	verdict, rc := "Good shape", th.Ok
	switch {
	case score < 30:
		verdict, rc = "At risk", th.Err
	case score < 60:
		verdict, rc = "Needs work", th.Warn
	}
	desc := "Nothing to fix."
	if fix := total - healthy; fix > 0 {
		desc = fmt.Sprintf("%d of %d credentials are healthy. Fix %d to reach 100.", healthy, total, fix)
	}

	const leftW = 30
	wide := w >= 80
	rightW := w
	if wide {
		rightW = w - leftW - 2
	}
	left := lipgloss.NewStyle().Width(leftW).Align(lipgloss.Center).Render(lipgloss.JoinVertical(lipgloss.Center,
		m.ring(score, rc), "", fg(th.Fg).Bold(true).Render(verdict),
		fg(th.Muted).Width(leftW-2).Align(lipgloss.Center).Render(desc)))

	barW := max(rightW-10-5, 4)
	bar := func(name string, n int, c color.Color, pending bool) string {
		count := fmt.Sprint(n)
		if pending {
			count = spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		}
		return fg(c).Width(10).Render(name) + m.meter(n, total, barW, c) +
			fg(th.Fg).Width(5).Align(lipgloss.Right).Render(count)
	}
	bars := lipgloss.JoinVertical(lipgloss.Left,
		bar("Healthy", healthy, th.Ok, false),
		bar("Reused", reused, th.Warn, false),
		bar("Weak", weak, th.Warn, false),
		bar("Breached", breached, th.Err, hs.running),
	)

	rows := []string{fg(th.Border).Render(strings.Repeat("─", rightW)), m.label("Needs attention")}
	if hs.running {
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		rows = append(rows, fg(th.Accent).Render(spin)+
			fg(th.Muted).Render(fmt.Sprintf("checking %d passwords against Have I Been Pwned…", total)), "")
	}
	if hs.failed > 0 {
		rows = append(rows, fg(th.Warn).Render("! breach check failed for "+credentials(hs.failed)+" (offline?)"), "")
	}
	if len(issues) == 0 {
		rows = append(rows, fg(th.Ok).Render("✓ Nothing needs attention"))
	}
	inner := rightW
	siteW := min(16, inner/3)
	for i, idx := range issues {
		e := &m.entries[idx]
		text, t, c := m.issue(e)
		base := lipgloss.NewStyle()
		marker := "  "
		if i == hs.cursor {
			base, marker = base.Background(th.Sel), "› "
		}
		tagS := m.tag(t, c)
		reasonW := max(inner-2-siteW-lipgloss.Width(tagS)-1, 0)
		rows = append(rows, base.Foreground(th.Accent).Render(marker)+
			base.Foreground(th.Fg).Bold(true).Width(siteW).Render(truncate(e.SiteName, siteW-1))+
			base.Foreground(th.Muted).Width(reasonW).Render(truncate(text, reasonW-1))+
			base.Render(" ")+tagS)
	}
	right := lipgloss.JoinVertical(lipgloss.Left, bars, "", strings.Join(rows, "\n"))
	body := lipgloss.JoinVertical(lipgloss.Left, left, right)
	if wide {
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	}
	body += "\n" + fg(th.Muted).Render("Breach check sends only a short hash prefix. Passwords never leave your device.")

	status := credentials(total) + " checked"
	if hs.running {
		status = "checking…"
	}
	return m.chrome(m.crumbs("vault health"), fg(th.Muted).Render(status), body,
		"AUDIT", "↑/↓", "move", "enter", "open item", "r", "re-run", "esc", "back")
}

// ring draws the score as a circular gauge filled clockwise from the top.
func (m *model) ring(score int, c color.Color) string {
	const w, h = 17, 9
	rx, ry := float64(w-1)/2, float64(h-1)/2
	cells := make([][]string, h)
	for y := range h {
		cells[y] = make([]string, w)
		for x := range w {
			dx, dy := (float64(x)-rx)/rx, (float64(y)-ry)/ry
			r := math.Hypot(dx, dy)
			if r < 0.72 || r > 1.08 {
				cells[y][x] = " "
				continue
			}
			a := math.Atan2(dx, -dy)
			if a < 0 {
				a += 2 * math.Pi
			}
			col := m.th.Border
			if a/(2*math.Pi)*100 < float64(score) {
				col = c
			}
			cells[y][x] = fg(col).Render("█")
		}
	}
	put := func(y int, s string, st lipgloss.Style) {
		start := (w - len(s)) / 2
		for i, r := range s {
			cells[y][start+i] = st.Render(string(r))
		}
	}
	put(h/2, fmt.Sprint(score), fg(m.th.Fg).Bold(true))
	put(h/2+1, "of 100", fg(m.th.Muted))
	rows := make([]string, h)
	for y := range h {
		rows[y] = strings.Join(cells[y], "")
	}
	return strings.Join(rows, "\n")
}
