package adscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strings"

	"wscan/internal/engine/js"
)

type gppSecret struct {
	XMLName   xml.Name
	User      string `xml:"userName,attr"`
	Name      string `xml:"name,attr"`
	CPassword string `xml:"cpassword,attr"`
	Changed   string `xml:"changed,attr"`
}

func sysvolAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	cred := o.Credential
	mode := "null"
	if cred.Username != "" {
		mode = "credential"
	}
	opt := js.SMBBrowseOptions{Host: o.Host, Port: 445, Mode: mode, Credential: cred, EntryLimit: 100}
	gppFiles := 0
	visited := 0
	for _, share := range []string{"SYSVOL", "NETLOGON"} {
		type node struct {
			dir   string
			depth int
		}
		queue := []node{{"", 0}}
		for len(queue) > 0 && visited < 2000 {
			if err := ctx.Err(); err != nil {
				return r, err
			}
			cur := queue[0]
			queue = queue[1:]
			entries, err := js.BrowseSMBWithOptions(ctx, opt, share, cur.dir)
			if err != nil {
				if cur.dir == "" {
					r.add("sysvol/"+share, "SMB "+share, "denied", "info", err.Error())
				}
				continue
			}
			for _, entry := range entries {
				visited++
				if visited > 2000 {
					break
				}
				remote := path.Join(cur.dir, entry.Name)
				if entry.Directory {
					if cur.depth < 10 && entry.Name != "." && entry.Name != ".." {
						queue = append(queue, node{remote, cur.depth + 1})
					}
					continue
				}
				switch strings.ToLower(path.Ext(entry.Name)) {
				case ".xml":
				default:
					continue
				}
				if entry.Size > 1<<20 || entry.Size <= 0 {
					continue
				}
				var buf strings.Builder
				_, err := js.ReadSMBFileWithOptions(ctx, opt, share, remote, &buf, 1<<20)
				if err != nil {
					continue
				}
				if buf.Len() == 0 || !strings.Contains(strings.ToLower(buf.String()), "cpassword") {
					continue
				}
				dec := xml.NewDecoder(strings.NewReader(buf.String()))
				count := 0
				for {
					tok, err := dec.Token()
					if err == io.EOF {
						break
					}
					if err != nil {
						break
					}
					start, ok := tok.(xml.StartElement)
					if !ok {
						continue
					}
					item := gppSecret{XMLName: start.Name}
					for _, attr := range start.Attr {
						switch strings.ToLower(attr.Name.Local) {
						case "username":
							item.User = attr.Value
						case "name":
							item.Name = attr.Value
						case "cpassword":
							item.CPassword = attr.Value
						case "changed":
							item.Changed = attr.Value
						}
					}
					if item.CPassword == "" {
						continue
					}
					// Detect the obsolete, reversible GPP password field, but never
					// decrypt or export credential material.
					count++
				}
				if count > 0 {
					gppFiles++
					r.add("gpp/"+remote, "GPP cpassword: "+remote, "confirmed", "high", fmt.Sprintf("Найдены устаревшие поля cpassword: %d; значения паролей не извлекались и не сохранялись", count))
				}
			}
		}
	}
	if visited >= 2000 {
		r.add("sysvol/limit", "SYSVOL / NETLOGON", "incomplete", "info", "Достигнут предел обхода 2000 записей или 500 секретов")
	}
	r.add("sysvol/summary", "SYSVOL / NETLOGON", "observed", "info", fmt.Sprintf("Обработано SMB-записей: %d; файлов с cpassword: %d", visited, gppFiles))
	return r, ctx.Err()
}
