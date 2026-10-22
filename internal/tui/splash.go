package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var logo = []string{
	" ██████╗  ██████╗ ██████╗  █████╗ ███████╗███████╗",
	"██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝",
	"██║  ███╗██║   ██║██████╔╝███████║███████╗███████╗",
	"██║   ██║██║   ██║██╔═══╝ ██╔══██║╚════██║╚════██║",
	"╚██████╔╝╚██████╔╝██║     ██║  ██║███████║███████║",
	" ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝",
}

const tagline = "zero-knowledge password manager"

var bootSteps = []string{"connecting to server", "loading Argon2id", "ready"}

const bootStepFrames = 3 // how long each boot step shows

// The splash plays once on its own (about a second) and any key skips it.
type splashState struct {
	rows   int // logo rows revealed so far
	step   int // bootSteps[:step] are done; bootSteps[step] is running
	stepAt int // frame the current step started
}

func (m *model) updateSplash(msg tea.Msg) tea.Cmd {
	s := &m.splash
	switch msg := msg.(type) {
	case tickMsg:
		if s.rows < len(logo) {
			s.rows++
		}
		// Step 0 waits for the first health check; later steps are timed.
		if m.frame-s.stepAt >= bootStepFrames && (s.step > 0 || m.checked) {
			s.step++
			s.stepAt = m.frame
			if s.step > len(bootSteps) {
				m.st = stateAuth
			}
		}
	case tea.KeyPressMsg:
		if msg.String() == "q" {
			return m.quit()
		}
		m.st = stateAuth
	}
	return nil
}

func (m *model) viewSplash() string {
	s, th := m.splash, m.th
	w, h := m.bodySize()

	// Logo with a left-to-right gradient, revealed row by row.
	var art []string
	if w >= lipgloss.Width(logo[0])+8 {
		colors := lipgloss.Blend1D(lipgloss.Width(logo[0]), th.Accent, th.Accent2, th.Fg, th.Accent2, th.Accent)
		for i, row := range logo {
			var b strings.Builder
			for x, r := range []rune(row) {
				if i < s.rows {
					b.WriteString(fg(colors[x]).Bold(true).Render(string(r)))
				} else {
					b.WriteByte(' ')
				}
			}
			art = append(art, b.String())
		}
	} else {
		art = []string{fg(th.Accent).Bold(true).Render("G O P A S S")}
	}

	// Tagline types itself out once the logo is in.
	typed := min(len(tagline), max(m.frame-2*len(logo), 0))
	line := fg(th.Fg).Render(tagline[:typed])
	if (m.frame/6)%2 == 0 {
		line += fg(th.Accent).Render("▏")
	}

	chip := func(s string) string {
		return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.Border).
			Padding(0, 1).Render(fg(th.Muted).Render(s))
	}
	chips := lipgloss.JoinHorizontal(lipgloss.Top, chip("AES-256-GCM"), " ", chip("Argon2id"), " ", chip("Bubble Tea"))

	var action string
	{
		spin := spinner.Dot.Frames[m.frame%len(spinner.Dot.Frames)]
		lines := make([]string, len(bootSteps))
		for i, name := range bootSteps {
			switch {
			case i < s.step && i == 0 && !m.online:
				lines[i] = fg(th.Warn).Render("✗ "+name) + fg(th.Muted).Render("  (offline)")
			case i < s.step:
				lines[i] = fg(th.Ok).Render("✓ ") + fg(th.Fg).Render(name)
			case i == s.step:
				lines[i] = fg(th.Accent).Render(spin) + fg(th.Muted).Render(name)
			}
		}
		block := strings.Join(lines, "\n")
		action = lipgloss.NewStyle().Width(lipgloss.Width(block)).Render(block)
	}

	plate := lipgloss.NewStyle().Padding(1, 4).Render(lipgloss.JoinVertical(lipgloss.Center,
		strings.Join(art, "\n"), "", line, "", chips, "", action))
	body := overlay(w, h, m.hexNoise(w, h), plate,
		(w-lipgloss.Width(plate))/2, (h-lipgloss.Height(plate))/2)

	return m.chrome(" "+fg(th.Muted).Render("v0.1.0"), fg(th.Accent2).Render("zero-knowledge · local-first"),
		body, "START", "any key", "skip", "q", "quit")
}

// hexNoise is the splash backdrop: dim rows of hex with a slow shimmer.
func (m *model) hexNoise(w, h int) string {
	dim := lipgloss.Blend1D(5, m.th.Bg, m.th.Muted)[1]
	glow := lipgloss.Blend1D(3, m.th.Bg, m.th.Accent)[1]
	rows := make([]string, h)
	for y := range h {
		var b strings.Builder
		for x := 0; x < w; x += 9 {
			g := fmt.Sprintf("%08x", hash32(y*131+x))
			g = g[:min(8, w-x)]
			c := dim
			if hash32(y*7919+x*31+m.frame/6)%13 == 0 {
				c = glow
			}
			b.WriteString(fg(c).Render(g))
			if x+9 <= w {
				b.WriteByte(' ')
			}
		}
		rows[y] = b.String()
	}
	return strings.Join(rows, "\n")
}

func hash32(n int) uint32 {
	x := uint32(n) * 2654435761
	x ^= x >> 16
	x *= 2246822519
	x ^= x >> 13
	return x
}
