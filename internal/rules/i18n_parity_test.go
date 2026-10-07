package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestI18nParityRejectsAmbiguousFlattenedKeys(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		`{"greeting.title":"hello","greeting":{"title":""}}`,
		`{"greeting":{"title":"hello"},"greeting.title":""}`,
		`{"greeting":{"title":"hello"},"greeting.title":false}`,
	} {
		root := t.TempDir()
		writeRuleFile(t, root, "languages.json", `{"languages":["en"]}`)
		writeRuleFile(t, root, "locales/en/translation.json", data)
		repo, err := repository.Open(root, repository.Options{})
		if err != nil {
			t.Fatal(err)
		}
		rule := baseRule("demo.i18n", "i18n.parity", nil, map[string]any{"manifest": "languages.json", "codesPointer": "/languages", "localesDirectory": "locales"})
		if _, err := (I18nParity{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule); err == nil || !strings.Contains(err.Error(), "ambiguous translation key") {
			t.Fatalf("ambiguous catalog %s accepted: %v", data, err)
		}
	}
}

func TestI18nParityRetainsMissingAndEmptyFindings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "languages.json", `{"languages":["en","de"]}`)
	writeRuleFile(t, root, "locales/en/translation.json", `{"greeting":{"title":"hello"},"empty":""}`)
	writeRuleFile(t, root, "locales/de/translation.json", `{"greeting":{"title":"hallo"}}`)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.i18n", "i18n.parity", nil, map[string]any{"manifest": "languages.json", "codesPointer": "/languages", "localesDirectory": "locales"})
	findings, err := (I18nParity{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want two empty/missing key findings, got %#v", findings)
	}
}
