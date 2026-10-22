package tui

import (
	"fmt"
	"hash/fnv"
	"image/color"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Shared widgets. Every screen renders its body and hands it to frame().

func fg(c color.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

// tint mixes c into the page background: a dim fill for pills and tags.
func (m *model) tint(c color.Color) color.Color { return lipgloss.Blend1D(5, m.th.Bg, c)[1] }

// size of the body area inside frame().
func (m *model) bodySize() (w, h int) { return max(m.w-4, 20), max(m.h-5, 6) }

// crumbs renders " › a › b" for the header.
func (m *model) crumbs(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(fg(m.th.Muted).Render(" › " + p))
	}
	return b.String()
}

// chrome draws the frame around a screen: brand + title and a right-hand
// status on top, then the body (with any toast over its bottom-right corner),
// then a rule and a footer with a mode badge, key hints and server status.
func (m *model) chrome(title, right, body, badge string, hints ...string) string {
	th := m.th
	w, h := m.bodySize()

	header := spread(fg(th.Accent).Bold(true).Render("gopass")+title, right, w)

	status := fg(th.Ok).Render("● ") + fg(th.Muted).Render("online")
	if !m.checked {
		status = fg(th.Muted).Render("● connecting")
	} else if !m.online {
		status = fg(th.Err).Render("● ") + fg(th.Muted).Render("offline")
	}
	if left := time.Until(m.clipUntil); m.clipHash != ([32]byte{}) && left > 0 {
		status = fg(th.Warn).Render(fmt.Sprintf("clipboard clears in %ds", int(left.Seconds())+1)) + "  " + status
	}
	footer := spread(m.pill(badge, th.Bg, th.Accent)+"  "+m.hints(hints...), status, w)

	body = lipgloss.NewStyle().Width(w).Height(h).MaxHeight(h).MaxWidth(w).Render(body)
	if t := m.toast; t != nil {
		box := m.viewToast(t)
		body = overlay(w, h, body, box, w-lipgloss.Width(box), h-1)
		body = lipgloss.NewStyle().Width(w).Height(h).Render(body)
	}
	return lipgloss.NewStyle().Padding(1, 2, 0).Render(lipgloss.JoinVertical(lipgloss.Left,
		header, "", body, fg(th.Border).Render(strings.Repeat("─", w)), footer))
}

func (m *model) viewToast(t *toast) string {
	c, icon := m.th.Ok, "✓ "
	if t.bad {
		c, icon = m.th.Err, "✗ "
	}
	bg := lipgloss.NewStyle().Background(m.th.Surface)
	s := bg.Foreground(c).Bold(true).Render(" " + icon + t.title)
	if t.sub != "" {
		s += bg.Foreground(m.th.Muted).Render(" · " + truncate(t.sub, 40))
	}
	return s + bg.Render(" ")
}

// spread puts left and right at the two ends of a line w cells wide.
func spread(left, right string, w int) string {
	gap := max(w-lipgloss.Width(left)-lipgloss.Width(right), 1)
	return left + strings.Repeat(" ", gap) + right
}

// hints renders "key label" pairs: keys bright, labels muted.
func (m *model) hints(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(fg(m.th.Fg).Bold(true).Render(pairs[i]) + " " + fg(m.th.Muted).Render(pairs[i+1]))
	}
	return b.String()
}

func (m *model) pill(text string, fgc, bg color.Color) string {
	return lipgloss.NewStyle().Foreground(fgc).Background(bg).Bold(true).Padding(0, 1).Render(text)
}

// tag is a small status pill like "reused" or "breached".
func (m *model) tag(text string, c color.Color) string {
	return lipgloss.NewStyle().Foreground(c).Background(m.tint(c)).Padding(0, 1).Render(text)
}

// card is a bordered panel.
func (m *model) card(content string, w int, border color.Color) string {
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).
		Padding(1, 2).Width(w).Render(content)
}

// label is the small uppercase caption above a value.
func (m *model) label(s string) string { return fg(m.th.Muted).Render(strings.ToUpper(s)) }

// avatarColor picks a stable color for a site by hashing its name.
func (m *model) avatarColor(site string) color.Color {
	palette := []color.Color{m.th.Accent, m.th.Accent2, m.th.Ok, m.th.Warn, m.th.Err}
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(site)))
	return palette[h.Sum32()%uint32(len(palette))]
}

func initial(site string) string {
	r, _ := utf8.DecodeRuneInString(site)
	if site == "" {
		return "?"
	}
	return string(unicode.ToUpper(r))
}

// avatar is a colored letter badge for a list row.
func (m *model) avatar(site string, sel color.Color) string {
	s := lipgloss.NewStyle().Foreground(m.th.Bg).Background(m.avatarColor(site)).Bold(true).
		Padding(0, 1).Render(initial(site))
	if sel != nil {
		s += lipgloss.NewStyle().Background(sel).Render(" ")
	} else {
		s += " "
	}
	return s
}

// autoLock is the header's "auto-lock 4:32 ━━━━━━" countdown.
func (m *model) autoLockBar() string {
	left := max(autoLock-time.Since(m.lastInput), 0)
	n := 10
	filled := int(float64(n) * float64(left) / float64(autoLock))
	c := m.th.Accent
	if left < 30*time.Second {
		c = m.th.Err
	}
	return fg(m.th.Muted).Render(fmt.Sprintf("auto-lock %d:%02d ", int(left.Minutes()), int(left.Seconds())%60)) +
		fg(c).Render(strings.Repeat("━", filled)) + fg(m.th.Border).Render(strings.Repeat("━", n-filled))
}

// meter is a horizontal bar of n cells, value/total filled.
func (m *model) meter(value, total, n int, c color.Color) string {
	filled := 0
	if total > 0 {
		filled = min(n, (value*n+total-1)/total)
	}
	return fg(c).Render(strings.Repeat("━", filled)) + fg(m.th.Border).Render(strings.Repeat("━", n-filled))
}

// strengthBar draws a 0-4 score as four segments plus a word.
func (m *model) strengthBar(score int) string {
	words := []string{"Very weak", "Weak", "Fair", "Good", "Strong"}
	colors := []color.Color{m.th.Err, m.th.Err, m.th.Warn, m.th.Ok, m.th.Ok}
	var b strings.Builder
	for i := range 4 {
		c := m.th.Border
		if i < score {
			c = colors[score]
		}
		b.WriteString(fg(c).Render("▬▬▬ "))
	}
	return b.String() + fg(colors[score]).Render(words[score])
}

// strength scores a password 0-4 from its length and character classes.
// It ranges over the bytes directly so no extra copy of the secret is made.
func strength(pw []byte) int {
	var lower, upper, digit, other bool
	n := 0
	for len(pw) > 0 {
		r, size := utf8.DecodeRune(pw)
		pw = pw[size:]
		n++
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{lower, upper, digit, other} {
		if ok {
			classes++
		}
	}
	switch {
	case n == 0:
		return 0
	case n < 8:
		return 1
	case n < 12 || classes < 3:
		return 2
	case n < 16 || classes < 4:
		return 3
	}
	return 4
}

// ago formats how long ago t was: "now", "5m", "3h", "2d", "3w", "4mo", "1y".
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dw", int(d.Hours()/24/7))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dmo", int(d.Hours()/24/30))
	}
	return fmt.Sprintf("%dy", int(d.Hours()/24/365))
}

// truncate cuts s to w cells with an ellipsis.
func truncate(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// overlay draws top over base at (x, y).
func overlay(w, h int, base, top string, x, y int) string {
	return lipgloss.NewCanvas(w, h).Compose(lipgloss.NewCompositor(
		lipgloss.NewLayer(base),
		lipgloss.NewLayer(top).X(max(x, 0)).Y(max(y, 0)).Z(1),
	)).Render()
}

// field is one text input. Its value is a []byte we own so wipe can zero it;
// that matters for passwords and is harmless for everything else.
type field struct {
	label       string
	placeholder string
	prefix      string // drawn before the value, e.g. "/ " on the filter
	plain       bool   // shown as typed; otherwise masked
	colored     bool   // plain, with digits and symbols highlighted (passwords being edited)
	words       bool   // recovery phrase: masked, plus a word count
	buf         []byte
}

func (f *field) wipe() {
	clear(f.buf)
	f.buf = nil
}

func (f *field) set(s string) {
	f.wipe()
	f.buf = appendSecret(nil, s)
}

// edit applies a typing key to the field and reports whether it used it.
func (f *field) edit(k tea.KeyPressMsg) bool {
	switch k.String() {
	case "backspace":
		if len(f.buf) > 0 {
			_, size := utf8.DecodeLastRune(f.buf)
			clear(f.buf[len(f.buf)-size:])
			f.buf = f.buf[:len(f.buf)-size]
		}
		return true
	case "ctrl+u":
		clear(f.buf)
		f.buf = f.buf[:0]
		return true
	}
	if k.Text != "" && k.Mod&^tea.ModShift == 0 {
		f.buf = appendSecret(f.buf, k.Text)
		return true
	}
	return false
}

// appendSecret appends s to buf, zeroing the old backing array if it has to grow.
func appendSecret(buf []byte, s string) []byte {
	if len(buf)+len(s) > cap(buf) {
		grown := make([]byte, len(buf), 2*cap(buf)+len(s)+32)
		copy(grown, buf)
		clear(buf)
		buf = grown
	}
	return append(buf, s...)
}

// display renders the value in at most w cells, keeping the tail visible.
func (f *field) display(w int) string {
	var s string
	switch {
	case f.plain || f.colored:
		s = string(f.buf)
	case f.words:
		count := fmt.Sprintf("  %d/24 words", len(splitFields(f.buf)))
		return strings.Repeat("•", min(utf8.RuneCount(f.buf), max(w-len(count), 0))) + count
	default:
		s = strings.Repeat("•", utf8.RuneCount(f.buf))
	}
	if r := []rune(s); len(r) > w {
		s = "…" + string(r[len(r)-w+1:])
	}
	return s
}

func splitFields(b []byte) [][]byte {
	var out [][]byte
	start := -1
	for i, c := range b {
		space := c == ' ' || c == '\n' || c == '\t' || c == '\r'
		switch {
		case !space && start < 0:
			start = i
		case space && start >= 0:
			out, start = append(out, b[start:i]), -1
		}
	}
	if start >= 0 {
		out = append(out, b[start:])
	}
	return out
}

// colorize highlights digits and symbols in a visible password.
func (m *model) colorize(s string) string {
	var b strings.Builder
	for _, r := range s {
		c := m.th.Fg
		switch {
		case unicode.IsDigit(r):
			c = m.th.Warn
		case !unicode.IsLetter(r):
			c = m.th.Accent
		}
		b.WriteString(fg(c).Render(string(r)))
	}
	return b.String()
}

// input renders a field as a labeled, bordered box.
func (m *model) input(f *field, focused bool, w int, bad bool) string {
	th := m.th
	border, labelC := th.Border, th.Muted
	if focused {
		border, labelC = th.Accent, th.Accent
	}
	if bad {
		border = th.Err
	}
	inner := w - 4 - lipgloss.Width(f.prefix)
	value := fg(th.Fg).Render(f.display(inner - 1))
	if f.colored {
		value = m.colorize(f.display(inner - 1))
	}
	if len(f.buf) == 0 && f.placeholder != "" {
		value = fg(th.Muted).Render(truncate(f.placeholder, inner-1))
	}
	value = fg(th.Accent).Render(f.prefix) + value
	if focused && (m.frame/6)%2 == 0 {
		value += lipgloss.NewStyle().Background(th.Accent).Render(" ")
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).
		Padding(0, 1).Width(w).Render(value)
	if f.label == "" {
		return box
	}
	return fg(labelC).Render(f.label) + "\n" + box
}

// credentials formats a count: "1 credential", "3 credentials".
func credentials(n int) string {
	if n == 1 {
		return "1 credential"
	}
	return fmt.Sprintf("%d credentials", n)
}
