package tui

import (
	"image/color"
	"os"

	"charm.land/lipgloss/v2"
)

// Theme is the palette every screen draws with. Colors are truecolor hex;
// Bubble Tea v2 detects the terminal's color profile and downsamples them
// to 256/16-color ANSI on terminals without truecolor.
type Theme struct {
	Name    string
	Bg      color.Color // page
	Surface color.Color // panels and inputs
	Sel     color.Color // selected row
	Fg      color.Color
	Muted   color.Color
	Accent  color.Color // brand, focus, badges
	Accent2 color.Color // secondary text (usernames, links)
	Ok      color.Color
	Warn    color.Color
	Err     color.Color
	Border  color.Color
}

func theme(name, bg, surface, sel, fg, muted, accent, accent2, ok, warn, err, border string) Theme {
	c := lipgloss.Color
	return Theme{name, c(bg), c(surface), c(sel), c(fg), c(muted), c(accent), c(accent2), c(ok), c(warn), c(err), c(border)}
}

var themes = []Theme{
	//     name        bg         surface    sel        fg         muted      accent     accent2    ok         warn       err        border
	theme("midnight", "#13141c", "#1a1c27", "#272a3c", "#e6e6f0", "#6c7086", "#f5a3c7", "#a99cf7", "#8fdba0", "#e9c46a", "#f28b8b", "#2c2f42"),
	theme("ember", "#17110f", "#201815", "#33241e", "#f2e3d5", "#7d6656", "#ff8a4c", "#ffbe73", "#a5c261", "#ffcc66", "#ff5f5f", "#3a2a22"),
	theme("mint", "#0e1715", "#13201d", "#1d332e", "#dff5ec", "#5f7f74", "#3ddc97", "#7ee8fa", "#3ddc97", "#f4d35e", "#ff6b6b", "#1f3530"),
	theme("phosphor", "#0a120c", "#0f1a12", "#163020", "#b8f5c4", "#4f7a5a", "#5cf08a", "#a8f0b8", "#5cf08a", "#e6ff4d", "#ff6b6b", "#1d3a25"),
	theme("ocean", "#0e1726", "#132036", "#1c2e4a", "#dde6f3", "#6c7f99", "#6fa8f5", "#9cc2ff", "#66d19e", "#ffca28", "#ef6b6b", "#22344f"),
	theme("violet", "#140f1f", "#1b1529", "#2b2140", "#e6dcf5", "#6d5f85", "#c4a7ff", "#f472b6", "#86efac", "#fcd34d", "#fb7185", "#2d2440"),
	theme("paper", "#f4f0e8", "#ece6da", "#e4d9c6", "#2e2a24", "#8a8275", "#c2416c", "#6b5bb5", "#3f7a2a", "#a66a00", "#b3261e", "#d6cbb8"),
	theme("snow", "#fafbfc", "#f0f2f5", "#e2e8f0", "#24292f", "#6e7781", "#d6336c", "#0969da", "#1a7f37", "#9a6700", "#cf222e", "#d0d7de"),
}

// themeFromEnv picks GOPASS_THEME, falling back to midnight.
func themeFromEnv() int {
	name := os.Getenv("GOPASS_THEME")
	for i, t := range themes {
		if t.Name == name {
			return i
		}
	}
	return 0
}
