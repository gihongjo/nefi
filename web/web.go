// Package web embeds the static UI files.
package web

import "embed"

//go:embed index.html topology.html
var Files embed.FS
