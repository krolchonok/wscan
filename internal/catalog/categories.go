package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// categoryEntry is one record from library/categories.json.
type categoryEntry struct {
	Path    string   `json:"path"`
	Kind    string   `json:"kind"`
	Service string   `json:"service"`
	Types   []string `json:"types"`
	Impact  string   `json:"impact"`
	Product string   `json:"product"`
	Tags    []string `json:"tags"`
	NSECats []string `json:"nse_categories"`
	Name    string   `json:"name"`
}

type categoriesFile struct {
	Version int                      `json:"version"`
	Entries map[string]categoryEntry `json:"entries"`
}

func (c *Catalog) ensureCategories() {
	c.categoriesMu.Lock()
	defer c.categoriesMu.Unlock()
	if c.categoriesLoaded {
		return
	}
	c.categoriesLoaded = true
	c.categories = map[string]categoryEntry{}
	if c.libraryDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(c.libraryDir, "categories.json"))
	if err != nil {
		if !os.IsNotExist(err) {
			c.categoriesError = fmt.Errorf("categories.json: %w", err)
		}
		return
	}
	c.categoriesPresent = true
	var doc categoriesFile
	if err := json.Unmarshal(data, &doc); err != nil || doc.Entries == nil || doc.Version != 1 {
		c.categoriesError = fmt.Errorf("categories.json: некорректный индекс или версия схемы")
		return
	}
	c.categories = doc.Entries
}

func (c *Catalog) categoryFor(path string) (categoryEntry, bool) {
	c.ensureCategories()
	c.categoriesMu.Lock()
	defer c.categoriesMu.Unlock()
	e, ok := c.categories[path]
	return e, ok
}

func applyCategory(entry *Entry, cat categoryEntry) {
	if cat.Service != "" {
		entry.Service = cat.Service
	}
	if cat.Impact != "" {
		entry.Impact = cat.Impact
	}
	if len(cat.Types) > 0 {
		entry.Type = strings.Join(cat.Types, ", ")
		entry.Category = strings.Join(cat.Types, ", ")
	}
	if cat.Product != "" {
		entry.Product = productLabel(cat.Product)
	}
	if cat.Name != "" {
		entry.SearchText = strings.TrimSpace(entry.SearchText + " " + cat.Name)
	}
	if len(cat.Tags) > 0 {
		entry.SearchText = strings.TrimSpace(entry.SearchText + " " + strings.Join(cat.Tags, " "))
	}
	if entry.Service != "" {
		entry.SearchText = strings.TrimSpace(entry.SearchText + " " + entry.Service)
	}
}

// The generated category index is the allowlist for a managed local library.
// Missing paths must not reappear by walking retained upstream source files.
func (c *Catalog) scopeAllows(path string) bool {
	c.ensureCategories()
	c.categoriesMu.Lock()
	defer c.categoriesMu.Unlock()
	if c.categoriesError != nil {
		return false
	}
	if !c.categoriesPresent {
		return true
	}
	_, ok := c.categories[path]
	return ok
}

func (c *Catalog) categoryIndexError() error {
	c.ensureCategories()
	c.categoriesMu.Lock()
	defer c.categoriesMu.Unlock()
	return c.categoriesError
}
