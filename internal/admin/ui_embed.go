package admin

import (
	"embed"
	"io/fs"
)

//go:embed ui/*
var embeddedUI embed.FS

func loadUIPage() ([]byte, error) {
	f, err := fs.ReadFile(embeddedUI, "ui/index.html")
	if err != nil {
		return nil, err
	}
	return f, nil
}
