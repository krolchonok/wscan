package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"

	"wscan/internal/domain"
)

type Data struct {
	Project string     `json:"project"`
	Run     domain.Run `json:"run"`
}

func Export(path, format string, data Data) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Write(f, format, data)
}

func Write(f io.Writer, format string, data Data) error {
	switch format {
	case "json":
		e := json.NewEncoder(f)
		e.SetIndent("", "  ")
		return e.Encode(data)
	case "csv":
		w := csv.NewWriter(f)
		_ = w.Write([]string{"record_type", "template_id", "name", "severity", "target", "matched_at", "risk", "evidence", "host", "port", "protocol", "service", "product", "version"})
		for _, x := range data.Run.Findings {
			_ = w.Write([]string{"finding", x.TemplateID, x.Name, x.Severity, x.Target, x.MatchedAt, x.Risk, x.Evidence, "", "", "", "", "", ""})
		}
		for _, s := range data.Run.Services {
			_ = w.Write([]string{"service", "", "", "", "", "", "", "", s.Host, fmt.Sprint(s.Port), s.Protocol, s.Name, s.Product, s.Version})
		}
		w.Flush()
		return w.Error()
	case "html":
		const page = `<!doctype html><meta charset="utf-8"><title>wscan report</title><style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>wscan report: {{.Project}}</h1><p>Run #{{.Run.ID}} · {{.Run.Status}} · {{len .Run.Findings}} findings · {{len .Run.Services}} services</p><h2>Open services</h2><pre>{{json .Run.Services}}</pre><h2>Findings</h2><pre>{{json .Run.Findings}}</pre>`
		t, err := template.New("report").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }}).Parse(page)
		if err != nil {
			return err
		}
		return t.Execute(f, data)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}
