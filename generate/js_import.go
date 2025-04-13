package generate

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/please-build/puku/kinds"
	"github.com/please-build/puku/logging"
)

var jslog = logging.GetLogger()

// JSFile represents a single JavaScript/TypeScript file in a package
type JSFile struct {
	// Name is the name from the source file
	Name, FileName string
	// Imports are the imports of this file
	Imports []string
}

// TSConfig represents a simplified tsconfig.json structure
type TSConfig struct {
	CompilerOptions struct {
		BaseURL string              `json:"baseUrl"`
		Paths   map[string][]string `json:"paths"`
	} `json:"compilerOptions"`
}

var (
	// Match PUKU ignore directive
	esPukuIgnoreRegex = regexp.MustCompile(`//\s*puku-ignore\s*$`)
	// Match ES module imports: import ... from "package";
	esImportRegex = regexp.MustCompile(`import\s+(?:.+\s+from\s+)?['"]([^'"]+)['"]`)

	// Match CommonJS require: const foo = require("package");
	requireRegex = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Match dynamic import: import("package")
	dynamicImportRegex = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

// ImportJSDir imports all JavaScript/TypeScript files from a directory
func ImportJSDir(dir string) (map[string]*JSFile, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	ret := make(map[string]*JSFile, len(files))
	for _, info := range files {
		if !info.Type().IsRegular() {
			continue
		}

		ext := filepath.Ext(info.Name())
		if ext != ".js" && ext != ".jsx" && ext != ".ts" && ext != ".tsx" {
			continue
		}

		f, skip, err := importJSFile(dir, info.Name())
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		ret[info.Name()] = f
	}

	return ret, nil
}

func importJSFile(dir, src string) (*JSFile, bool, error) {
	log.Debugf("importJSFile: Analyzing dir: %s, src: %s", dir, src)
	file, err := os.Open(filepath.Join(dir, src))
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	imports := make([]string, 0)
	uniqueImports := make(map[string]struct{})

	for scanner.Scan() {
		line := scanner.Text()
		log.Debugf("importJSFile: line: %s", line)
		matches := esPukuIgnoreRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			log.Debugf("importJSFile: found puku-ignore directive")
			return nil, true, nil
		}

		// Process ES imports
		matches = esImportRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			log.Debugf("importJSFile: found ES import: %s", matches[1])
			if _, ok := uniqueImports[matches[1]]; !ok {
				uniqueImports[matches[1]] = struct{}{}
				imports = append(imports, matches[1])
			}
			continue
		}

		// Process require
		matches = requireRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			log.Debugf("importJSFile: found require: %s", matches[1])
			if _, ok := uniqueImports[matches[1]]; !ok {
				uniqueImports[matches[1]] = struct{}{}
				imports = append(imports, matches[1])
			}
			continue
		}

		// Process dynamic import
		matches = dynamicImportRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			log.Debugf("importJSFile: found dynamic import: %s", matches[1])
			if _, ok := uniqueImports[matches[1]]; !ok {
				uniqueImports[matches[1]] = struct{}{}
				imports = append(imports, matches[1])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, false, err
	}

	return &JSFile{
		Name:     filepath.Base(src),
		FileName: src,
		Imports:  imports,
	}, false, nil
}

func (f *JSFile) IsTest() bool {
	return strings.HasSuffix(f.FileName, ".test.js") ||
		strings.HasSuffix(f.FileName, ".test.jsx") ||
		strings.HasSuffix(f.FileName, ".test.ts") ||
		strings.HasSuffix(f.FileName, ".test.tsx") ||
		strings.HasSuffix(f.FileName, ".spec.js") ||
		strings.HasSuffix(f.FileName, ".spec.jsx") ||
		strings.HasSuffix(f.FileName, ".spec.ts") ||
		strings.HasSuffix(f.FileName, ".spec.tsx")
}

func (f *JSFile) kindType() kinds.Type {
	if f.IsTest() {
		return kinds.Test
	}
	return kinds.Lib
}

// ParseJSONC reads a JSONC file (JSON with comments) and returns a JSON string
func ParseJSONC(data []byte) ([]byte, error) {
	// Remove single-line comments
	re := regexp.MustCompile(`(?m)//.*$`)
	data = re.ReplaceAll(data, []byte(""))

	// Remove multi-line comments
	re = regexp.MustCompile(`(?s)/\*.*?\*/`)
	data = re.ReplaceAll(data, []byte(""))

	// Remove trailing commas in objects and arrays
	re = regexp.MustCompile(`,\s*}`)
	data = re.ReplaceAll(data, []byte("}"))
	re = regexp.MustCompile(`,\s*\]`)
	data = re.ReplaceAll(data, []byte("]"))

	return data, nil
}

// FindTSConfig searches for a tsconfig.json file in the given directory and up the tree
func FindTSConfig(dir string) (*TSConfig, string, error) {
	currentDir := dir
	for {
		tsconfigPath := filepath.Join(currentDir, "tsconfig.json")
		if _, err := os.Stat(tsconfigPath); err == nil {
			// Read the file
			data, err := os.ReadFile(tsconfigPath)
			if err != nil {
				return nil, "", err
			}

			// Parse JSONC to JSON
			jsonData, err := ParseJSONC(data)
			if err != nil {
				jslog.Warningf("Failed to parse tsconfig.json at %s: %v", tsconfigPath, err)
				return nil, currentDir, nil
			}

			// Unmarshal JSON
			var tsConfig TSConfig
			if err := json.Unmarshal(jsonData, &tsConfig); err != nil {
				jslog.Warningf("Failed to unmarshal tsconfig.json at %s: %v", tsconfigPath, err)
				return nil, currentDir, nil
			}

			return &tsConfig, currentDir, nil
		}

		// Move up one directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// We've reached the root directory
			break
		}
		currentDir = parentDir
	}

	// No tsconfig.json found
	return nil, "", nil
}

// ResolveJSImport converts JS/TS imports to appropriate BUILD targets
func ResolveJSImport(importPath string, currentDir string) (string, bool) {
	log.Debugf("ResolveJSImport: path=%s, dir=%s", importPath, currentDir)
	// Special case: handle @ prefix for internal packages according to the example
	if strings.HasPrefix(importPath, "@/") {
		// TODO(ryan): Improve this to actually use and understand the path mapping?
		// Convert @/services/catalog/proto -> //services/catalog/proto
		return "//" + importPath[2:], false
	}

	if strings.HasPrefix(importPath, "~/") {
		// Ignore remix local (intra-app) imports.
		//
		// TODO(ryan): Think of a better way to accommodate this bs. I'm not sure if it'll come from devising a better way
		// to handle the bundling of remix related shenanigans or by somehow making this a bit of configuration or what.
		// but this will do for now.
		return "", true
	}

	// Try to find a tsconfig.json to use for path mapping
	tsConfig, tsConfigDir, err := FindTSConfig(currentDir)
	if err != nil {
		jslog.Warningf("Error finding tsconfig.json: %v", err)
	}

	if tsConfig != nil && len(tsConfig.CompilerOptions.Paths) > 0 {
		// Try to match the import path against the path patterns
		for pattern, targets := range tsConfig.CompilerOptions.Paths {
			// Convert TypeScript path pattern to regexp
			// For example: "@/*" -> "^@/(.*)$"
			regexPattern := "^" + strings.ReplaceAll(pattern, "*", "(.*)") + "$"
			regex, err := regexp.Compile(regexPattern)
			if err != nil {
				jslog.Warningf("Invalid pattern in tsconfig.json: %s", pattern)
				continue
			}

			match := regex.FindStringSubmatch(importPath)
			if match != nil && len(targets) > 0 {
				// Get the first target pattern and replace the asterisk with the captured group
				target := targets[0]
				if len(match) > 1 {
					target = strings.ReplaceAll(target, "*", match[1])
				}

				// If it's a relative path, make it absolute from the tsconfig location
				if !strings.HasPrefix(target, "/") {
					// Calculate the target relative to the project root
					relPath := filepath.Join(tsConfigDir, target)
					// Convert to a BUILD target path
					return "//" + filepath.ToSlash(relPath), false
				}

				// TODO(ryan): This can be removed, but I'll do that in the cleanup pass.
				// If already a BUILD target (starts with //), return as is
				if strings.HasPrefix(target, "//") {
					return target, false
				}

				// Otherwise, treat as a local path
				return "//" + target, false
			}
		}
	}

	// Default to third-party for non-mapped paths with the format ///third_party/js/npm//:package_with_underscores
	return "///third_party/js/npm//:" + strings.ReplaceAll(GetNPMPackageName(importPath), "/", "_"), false
}

func GetNPMPackageName(importPath string) string {
	idx := strings.Index(importPath, "/")
	if idx == -1 {
		return importPath
	}

	if strings.HasPrefix(importPath, "@") {
		sidx := strings.Index(importPath[idx+1:], "/")
		if sidx == -1 {
			return importPath
		}
		return importPath[:idx+sidx+1]
	}
	return importPath[:idx]
}
