package featureparity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Catalog struct {
	Items []Item `json:"items"`
}

type Item struct {
	FeatureID   string   `json:"feature_id"`
	Feature     string   `json:"feature"`
	ServedState string   `json:"served_state"`
	APISurface  []string `json:"api_surface"`
	APINA       string   `json:"api_na"`
	CLISurface  []string `json:"cli_surface"`
	CLINA       string   `json:"cli_na"`
}

func Load() (Catalog, error) {
	root, err := repoRoot()
	if err != nil {
		return Catalog{}, err
	}
	b, err := os.ReadFile(filepath.Join(root, "web", "src", "lib", "feature-map-backlog.json"))
	if err != nil {
		return Catalog{}, fmt.Errorf("read feature-map backlog: %w", err)
	}
	var catalog Catalog
	if err := json.Unmarshal(b, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("parse feature-map backlog: %w", err)
	}
	if len(catalog.Items) != 78 {
		return Catalog{}, fmt.Errorf("feature-map backlog rows = %d, want 78", len(catalog.Items))
	}
	return catalog, nil
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repository root containing go.mod")
		}
		dir = parent
	}
}
