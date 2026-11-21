package report

import (
	"fmt"
	"math"
	"strings"
)

// A tiny SVG line chart: no scripts, no fonts, no services, so a report opens anywhere.

type Line struct {
	Name string
	X, Y []float64
}

var palette = []string{"#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf", "#8c564b", "#7f7f7f"}

func niceMax(v float64) float64 {
	if v <= 0 {
		return 1
	}
	e := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if v <= m*e {
			return m * e
		}
	}
	return 10 * e
}

func fmtNum(v float64) string {
	switch {
	case v >= 1000:
		return fmt.Sprintf("%.0f", v)
	case v >= 10:
		return fmt.Sprintf("%.0f", v)
	case v >= 1:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.2g", v)
	}
}

// lineChart draws lines over a shared x axis (seconds). markers are vertical lines (the steps).
func lineChart(title, ylabel string, lines []Line, markers []float64) string {
	const W, H, L, R, T, B = 760, 250, 56, 14, 28, 34
	var xmax, ymax float64
	for _, l := range lines {
		for i := range l.X {
			xmax = math.Max(xmax, l.X[i])
			ymax = math.Max(ymax, l.Y[i])
		}
	}
	if xmax == 0 {
		return fmt.Sprintf(`<figure><figcaption>%s</figcaption><p class="muted">no data</p></figure>`, esc(title))
	}
	ymax = niceMax(ymax * 1.05)
	px := func(x float64) float64 { return L + x/xmax*(W-L-R) }
	py := func(y float64) float64 { return H - B - y/ymax*(H-T-B) }
	var b strings.Builder
	fmt.Fprintf(&b, `<figure><figcaption>%s</figcaption><svg viewBox="0 0 %d %d" role="img" aria-label="%s">`, esc(title), W, H, esc(title))
	for i := 0; i <= 4; i++ {
		y := ymax * float64(i) / 4
		fmt.Fprintf(&b, `<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="grid"/><text x="%d" y="%.1f" class="tick" text-anchor="end">%s</text>`, L, W-R, py(y), py(y), L-6, py(y)+4, fmtNum(y))
	}
	for i := 0; i <= 5; i++ {
		x := xmax * float64(i) / 5
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" class="tick" text-anchor="middle">%s</text>`, px(x), H-B+16, fmtNum(x))
	}
	fmt.Fprintf(&b, `<text x="%d" y="%d" class="tick" text-anchor="middle">seconds since the arrivals began</text><text x="12" y="%d" class="tick" transform="rotate(-90 12 %d)" text-anchor="middle">%s</text>`, (L+W-R)/2, H-4, (T+H-B)/2, (T+H-B)/2, esc(ylabel))
	for _, m := range markers {
		fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" class="mark"/>`, px(m), px(m), T, H-B)
	}
	for i, l := range lines {
		c := palette[i%len(palette)]
		var pts []string
		for j := range l.X {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", px(l.X[j]), py(l.Y[j])))
		}
		fmt.Fprintf(&b, `<polyline fill="none" stroke="%s" stroke-width="1.8" points="%s"/>`, c, strings.Join(pts, " "))
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="10" height="3" fill="%s"/><text x="%d" y="%d" class="tick">%s</text>`, L+8+i*150, 8, c, L+22+i*150, 13, esc(l.Name))
	}
	b.WriteString(`</svg></figure>`)
	return b.String()
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
