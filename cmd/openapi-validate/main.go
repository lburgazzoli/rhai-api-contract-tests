// Command openapi-validate revalidates an OpenAPI document with ECMAScript
// patterns when oasdiff's Go regexp compiler rejects its pattern syntax.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oasdiff/oasdiff/validate"
)

type finding struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Level int    `json:"level"`
}

// kin-openapi's matcher interface cannot return execution errors. Keep them
// separately so a regex timeout is a tool error, not a successful validation.
type compiler struct{ matchError error }

type matcher struct {
	pattern *regexp2.Regexp
	owner   *compiler
}

func (m matcher) MatchString(value string) bool {
	matched, err := m.pattern.MatchString(value)
	if err != nil {
		m.owner.matchError = err
	}
	return matched
}

func (c *compiler) compile(pattern string) (openapi3.RegexMatcher, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = time.Second
	return matcher{pattern: re, owner: c}, nil
}

func appendFindings(out []finding, err error) []finding {
	if err == nil {
		return out
	}
	if multiple, ok := err.(openapi3.MultiError); ok {
		for _, item := range multiple {
			out = appendFindings(out, item)
		}
		return out
	}
	id := "spec-validation-error"
	var coded openapi3.CodedError
	if errors.As(err, &coded) {
		id = coded.Code()
	}
	return append(out, finding{ID: id, Text: err.Error(), Level: int(validate.RuleLevel(id))})
}

func validateDocument(path string) ([]finding, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	patterns := &compiler{}
	err = doc.Validate(context.Background(), openapi3.EnableMultiError(), openapi3.SetRegexCompiler(patterns.compile))
	if patterns.matchError != nil {
		return nil, fmt.Errorf("ECMAScript regex evaluation failed: %w", patterns.matchError)
	}
	return appendFindings([]finding{}, err), nil
}

func version() string {
	text := "openapi-validate"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/getkin/kin-openapi" || dep.Path == "github.com/dlclark/regexp2" || dep.Path == "github.com/oasdiff/oasdiff" {
				text += " " + dep.Path + "@" + dep.Version
			}
		}
	}
	return text
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, version())
		return 0
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: openapi-validate <document.yaml|document.json>")
		return 2
	}
	records, err := validateDocument(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "openapi-validate:", err)
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(records); err != nil {
		fmt.Fprintln(stderr, "openapi-validate:", err)
		return 2
	}
	for _, record := range records {
		if record.Level >= 3 {
			return 1
		}
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
