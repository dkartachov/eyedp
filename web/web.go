// Package web embeds the HTML templates for browser-facing pages.
package web

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var files embed.FS

// Templates holds every page template, keyed by file name (e.g. "login.html").
var Templates = template.Must(template.ParseFS(files, "templates/*.html"))
