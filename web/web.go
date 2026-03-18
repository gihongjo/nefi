// Package web embeds the Svelte build output (ui/dist → web/dist).
package web

import "embed"

//go:embed dist
var Files embed.FS
