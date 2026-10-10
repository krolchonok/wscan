package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"wscan/internal/domain"
)

type Metadata struct {
	Name           string
	Description    string
	Impact         string
	Remediation    string
	Classification string
	References     []string
	Path           string
}

var scriptDescriptionRE = regexp.MustCompile(`(?s)description\s*=\s*\[=*\[(.*?)\]=*\]`)

// Metadata reads local documentation without re-running the check. The caller
// keeps this explanation separate from actual historical scan evidence.
func (c *Catalog) Metadata(id string) (Metadata, bool) {
	if c.libraryDir == "" {
		return Metadata{}, false
	}
	c.metadataMu.RLock()
	path := c.metadataPaths[id]
	c.metadataMu.RUnlock()
	if strings.HasPrefix(id, "nmap/") {
		path = "nmap/scripts/" + filepath.Base(strings.TrimPrefix(id, "nmap/")) + ".nse"
	}
	if path == "" {
		return Metadata{}, false
	}
	root := c.libraryDir
	if !strings.HasPrefix(path, "nmap/") {
		root = filepath.Join(root, "nuclei-templates")
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return Metadata{}, false
	}
	meta := Metadata{Path: path}
	if strings.HasPrefix(path, "nmap/") {
		meta.Name = strings.TrimPrefix(id, "nmap/")
		if match := scriptDescriptionRE.FindSubmatch(data); len(match) == 2 {
			meta.Description = strings.TrimSpace(string(match[1]))
		}
		return meta, true
	}
	var doc struct {
		ID   string `yaml:"id"`
		Info struct {
			Name           string            `yaml:"name"`
			Description    string            `yaml:"description"`
			Impact         string            `yaml:"impact"`
			Remediation    string            `yaml:"remediation"`
			Reference      domain.StringList `yaml:"reference"`
			Classification struct {
				CVSSMetrics string  `yaml:"cvss-metrics"`
				CVSSScore   float64 `yaml:"cvss-score"`
				CVEID       string  `yaml:"cve-id"`
				CWEID       string  `yaml:"cwe-id"`
			} `yaml:"classification"`
		} `yaml:"info"`
	}
	if yaml.Unmarshal(data, &doc) != nil || doc.ID != id {
		return Metadata{}, false
	}
	meta.Name = doc.Info.Name
	meta.Description = strings.TrimSpace(doc.Info.Description)
	meta.Impact = strings.TrimSpace(doc.Info.Impact)
	meta.Remediation = strings.TrimSpace(doc.Info.Remediation)
	meta.References = doc.Info.Reference
	meta.Classification = formatClassification(
		doc.Info.Classification.CVSSScore,
		doc.Info.Classification.CVSSMetrics,
		doc.Info.Classification.CVEID,
		doc.Info.Classification.CWEID,
	)
	return meta, true
}

// formatClassification builds a compact one-line severity reference from the
// template's own classification block. Empty fields are skipped; it never
// invents a score the template did not state.
func formatClassification(cvssScore float64, cvssMetrics, cveID, cweID string) string {
	var parts []string
	if cvssScore > 0 {
		if cvssMetrics != "" {
			parts = append(parts, fmt.Sprintf("CVSS %.1f (%s)", cvssScore, cvssMetrics))
		} else {
			parts = append(parts, fmt.Sprintf("CVSS %.1f", cvssScore))
		}
	} else if cvssMetrics != "" {
		parts = append(parts, cvssMetrics)
	}
	if cveID != "" {
		parts = append(parts, cveID)
	}
	if cweID != "" {
		parts = append(parts, cweID)
	}
	return strings.Join(parts, " · ")
}
