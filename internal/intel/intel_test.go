package intel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestThreatFeedSTIXCIDRAndAssetCriticality(t *testing.T) {
	dir := t.TempDir()
	stixPath := filepath.Join(dir, "stix.json")
	cidrPath := filepath.Join(dir, "blocklist.txt")

	stixBody := `{
  "type": "bundle",
  "id": "bundle--11111111-1111-1111-1111-111111111111",
  "objects": [
    {
      "type": "indicator",
      "name": "Synthetic C2 Domain",
      "confidence": 90,
      "pattern": "[domain-name:value = 'c2-drop.example.invalid']"
    },
    {
      "type": "indicator",
      "name": "Synthetic Scanner IP",
      "pattern": "[ipv4-addr:value = '198.51.100.222']"
    }
  ]
}`
	if err := os.WriteFile(stixPath, []byte(stixBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cidrPath, []byte("# RFC 5737 subnet\n203.0.113.128/25\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	feed := NewThreatFeed()
	if err := feed.LoadFile(stixPath); err != nil {
		t.Fatalf("LoadFile stix: %v", err)
	}
	if err := feed.LoadFile(cidrPath); err != nil {
		t.Fatalf("LoadFile cidr: %v", err)
	}
	if feed.Count() != 3 {
		t.Fatalf("expected 3 loaded indicators, got %d", feed.Count())
	}

	hits := feed.MatchEvent(schema.Event{
		SrcIP: "203.0.113.200",
		Metadata: map[string]any{
			"domain": "c2-drop.example.invalid",
		},
	})
	if len(hits) != 2 {
		t.Fatalf("expected 2 intel matches (CIDR + STIX domain), got %+v", hits)
	}

	cat, err := NewAssetCatalog([]AssetEntry{
		{Host: "prod-db-01", Tier: "tier1", Owner: "platform-sec"},
		{CIDR: "198.51.100.0/24", Tier: "tier2"},
	})
	if err != nil {
		t.Fatalf("NewAssetCatalog failed: %v", err)
	}
	asset, ok := cat.LookupHostOrIP("prod-db-01", "")
	if !ok || asset.Tier != "tier1" || asset.Owner != "platform-sec" {
		t.Fatalf("unexpected asset lookup: %+v ok=%v", asset, ok)
	}
	esc, changed := EscalateSeverity(schema.SeverityHigh, asset.Tier)
	if !changed || esc != schema.SeverityCritical {
		t.Fatalf("expected tier1 high->critical escalation, got %s (%v)", esc, changed)
	}
}
