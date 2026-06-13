package registry

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
)

var riskyImports = map[string]string{
	"C":              "cgo can bypass portable sandbox assumptions",
	"os/exec":        "process execution must be reviewed",
	"plugin":         "dynamic plugin loading must be reviewed",
	"syscall":        "direct syscalls must be reviewed",
	"unsafe":         "unsafe memory access must be reviewed",
	"net/http/pprof": "debug HTTP endpoints must not be exposed by plugins",
}

// AuditFinding is one source policy finding.
type AuditFinding struct {
	Path    string
	Line    int
	Message string
}

func (f AuditFinding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", f.Path, f.Line, f.Message)
	}
	return fmt.Sprintf("%s: %s", f.Path, f.Message)
}

// AuditSource flags high-risk source patterns for maintainer review. It is a
// review aid, not a malware detector.
func AuditSource(root string) ([]AuditFinding, error) {
	var findings []AuditFinding
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if why, ok := riskyImports[importPath]; ok {
				pos := fset.Position(imp.Pos())
				findings = append(findings, AuditFinding{Path: path, Line: pos.Line, Message: fmt.Sprintf("import %q: %s", importPath, why)})
			}
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "init" {
					pos := fset.Position(d.Pos())
					findings = append(findings, AuditFinding{Path: path, Line: pos.Line, Message: "init function runs before plugin handshake"})
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, value := range vs.Values {
						if containsCall(value) {
							pos := fset.Position(value.Pos())
							findings = append(findings, AuditFinding{Path: path, Line: pos.Line, Message: "package-level function call runs during initialization"})
						}
					}
				}
			}
		}
		return nil
	})
	return findings, err
}

func containsCall(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}
