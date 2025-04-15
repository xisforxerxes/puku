package generate

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/please-build/buildtools/build"
	"github.com/please-build/buildtools/labels"

	"github.com/please-build/puku/config"
	"github.com/please-build/puku/edit"
	"github.com/please-build/puku/eval"
	"github.com/please-build/puku/glob"
	"github.com/please-build/puku/graph"
	"github.com/please-build/puku/kinds"
	"github.com/please-build/puku/licences"
	"github.com/please-build/puku/logging"
	"github.com/please-build/puku/options"
	"github.com/please-build/puku/please"
	"github.com/please-build/puku/proxy"
	"github.com/please-build/puku/trie"
)

var log = logging.GetLogger()

type Proxy interface {
	ResolveModuleForPackage(pattern string) (*proxy.Module, error)
	ResolveDeps(mods, newMods []*proxy.Module) ([]*proxy.Module, error)
}

type updater struct {
	plzConf       *please.Config
	usingGoModule bool

	graph *graph.Graph

	newModules      []*proxy.Module
	modules         []string
	resolvedImports map[string]string
	installs        *trie.Trie
	eval            *eval.Eval

	paths []string

	proxy    Proxy
	licences *licences.Licenses
}

func newUpdaterWithGraph(g *graph.Graph, conf *please.Config) *updater {
	p := proxy.New(proxy.DefaultURL)
	l := licences.New(p, g)
	return &updater{
		proxy:           p,
		licences:        l,
		plzConf:         conf,
		graph:           g,
		installs:        trie.New(),
		eval:            eval.New(glob.New()),
		resolvedImports: map[string]string{},
	}
}

// newUpdater initialises a new updater struct. It's intended to be only used for testing (as is
// newUpdaterWithGraph). In most instances the Update function should be called directly.
func newUpdater(conf *please.Config, opts options.Options) *updater {
	g := graph.New(conf.BuildFileNames(), opts).WithExperimentalDirs(conf.Parse.ExperimentalDir...)

	return newUpdaterWithGraph(g, conf)
}

func Update(plzConf *please.Config, opts options.Options, paths ...string) error {
	u := newUpdater(plzConf, opts)
	if err := u.update(paths...); err != nil {
		return err
	}
	return u.graph.FormatFiles()
}

func UpdateToStdout(format string, plzConf *please.Config, opts options.Options, paths ...string) error {
	u := newUpdater(plzConf, opts)
	if err := u.update(paths...); err != nil {
		return err
	}
	return u.graph.FormatFilesWithWriter(os.Stdout, format)
}

func (u *updater) readAllModules(conf *config.Config) error {
	return filepath.WalkDir(conf.GetThirdPartyDir(), func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		for _, buildFileName := range u.plzConf.BuildFileNames() {
			if info.Name() == buildFileName {
				file, err := u.graph.LoadFile(filepath.Dir(path))
				if err != nil {
					return err
				}

				if err := u.readModules(file); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// readModules returns the defined third party modules in this project
func (u *updater) readModules(file *build.File) error {
	addInstalls := func(targetName, modName string, installs []string) {
		for _, install := range installs {
			path := filepath.Join(modName, install)
			target := edit.BuildTarget(targetName, file.Pkg, "")
			u.installs.Add(path, target)
		}
	}

	for _, repoRule := range file.Rules("go_repo") {
		module := repoRule.AttrString("module")
		u.modules = append(u.modules, module)

		// we do not add installs for go_repos. We prefer to resolve deps
		// to the subrepo targets since this is more efficient for please.
	}

	goMods := file.Rules("go_module")
	u.usingGoModule = len(goMods) > 0 || u.usingGoModule

	for _, mod := range goMods {
		module := mod.AttrString("module")
		installs := mod.AttrStrings("install")
		if len(installs) == 0 {
			installs = []string{"."}
		}
		addInstalls(mod.Name(), module, installs)
	}

	return nil
}

// update loops through the provided paths, updating and creating any build rules it finds.
func (u *updater) update(paths ...string) error {
	conf, err := config.ReadConfig(".")
	if err != nil {
		return err
	}
	u.paths = paths

	if err := u.readAllModules(conf); err != nil {
		return fmt.Errorf("failed to read third party rules: %v", err)
	}

	for _, path := range u.paths {
		conf, err := config.ReadConfig(path)
		if err != nil {
			return err
		}

		if conf.GetStop() {
			return nil
		}

		if err := u.updateOne(conf, path); err != nil {
			return fmt.Errorf("failed to update %v: %v", path, err)
		}
	}

	// Save any new modules we needed back to the third party file
	return u.addNewModules(conf)
}

func (u *updater) updateOne(conf *config.Config, path string) error {
	// Find all the Go files in the dir
	goSources, err := ImportDir(path)
	if err != nil {
		return err
	}

	// Find all JS/TS files in the dir
	jsSources, err := ImportJSDir(path)
	if err != nil {
		return err
	}

	// Parse the build file
	file, err := u.graph.LoadFile(path)
	if err != nil {
		return err
	}

	if !u.plzConf.GoIsPreloaded() && conf.ShouldEnsureSubincludes() {
		edit.EnsureSubinclude(file)
	}

	// Read existing rules from file
	rules, calls := u.readRulesFromFile(conf, file, path)

	// Allocate the Go sources to the rules, creating new rules as necessary
	newGoRules, err := u.allocateSources(conf, path, goSources, rules)
	if err != nil {
		return err
	}

	rules = append(rules, newGoRules...)

	// Allocate the JS/TS sources to the rules, creating new rules as necessary
	newJSRules, err := u.allocateJSSources(conf, path, jsSources, rules)
	if err != nil {
		return err
	}

	rules = append(rules, newJSRules...)

	// Update the existing call expressions in the build file - first for Go
	if err := u.updateDeps(conf, file, calls, rules, goSources); err != nil {
		return err
	}

	// Then for JS/TS
	return u.updateJSDeps(conf, file, calls, rules, jsSources)
}

func (u *updater) addNewModules(conf *config.Config) error {
	file, err := u.graph.LoadFile(conf.GetThirdPartyDir())
	if err != nil {
		return err
	}

	if !u.plzConf.GoIsPreloaded() && conf.ShouldEnsureSubincludes() {
		edit.EnsureSubinclude(file)
	}

	goRepos := file.Rules("go_repo")
	mods := make([]*proxy.Module, 0, len(goRepos))
	existingRules := make(map[string]*build.Rule)
	for _, rule := range goRepos {
		mod, ver := rule.AttrString("module"), rule.AttrString("version")
		existingRules[rule.AttrString("module")] = rule
		mods = append(mods, &proxy.Module{Module: mod, Version: ver})
	}

	allMods, err := u.proxy.ResolveDeps(mods, u.newModules)
	if err != nil {
		return err
	}

	for _, mod := range allMods {
		if rule, ok := existingRules[mod.Module]; ok {
			// Modules might be using go_mod_download, which we don't handle.
			if rule.Attr("version") != nil {
				rule.SetAttr("version", edit.NewStringExpr(mod.Version))
			}
			continue
		}
		ls, err := u.licences.Get(mod.Module, mod.Version)
		if err != nil {
			return fmt.Errorf("failed to get license for mod %v: %v", mod.Module, err)
		}
		file.Stmt = append(file.Stmt, edit.NewGoRepoRule(mod.Module, mod.Version, "", ls, []string{}))
	}
	return nil
}

// allSources calculates the sources for a target. It will evaluate the source list resolving globs, and building any
// srcs that are other build targets.
//
// passedSources is a slice of filepaths, which contains source files passed to the rule, after resolving globs and
// building any targets. These source files can be looked up in goFiles, if they exist.
//
// goFiles contains a mapping of source files to their GoFile. This map might be missing entries from passedSources, if
// the source doesn't actually exist. In which case, this should be removed from the rule, as the user likely deleted
// the file.
func (u *updater) allSources(conf *config.Config, r *edit.Rule, sourceMap map[string]*GoFile) (passedSources []string, goFiles map[string]*GoFile, err error) {
	srcs, err := u.eval.BuildSources(conf.GetPlzPath(), r.Dir, r.Rule, r.SrcsAttr())
	if err != nil {
		return nil, nil, err
	}

	sources := make(map[string]*GoFile, len(srcs))
	for _, src := range srcs {
		if file, ok := sourceMap[src]; ok {
			sources[src] = file
			continue
		}

		// These are generated sources in plz-out/gen
		f, err := importFile(".", src)
		if err != nil {
			continue
		}
		sources[src] = f
	}
	return srcs, sources, nil
}

func setExternal(rule *edit.Rule) {
	rule.SetAttr("external", &build.Ident{Name: "True"})
}

func isExternal(rule *edit.Rule) bool {
	if !rule.IsTest() {
		return false
	}

	external := rule.Attr("external")
	if external == nil {
		return false
	}

	ident, ok := external.(*build.Ident)
	if !ok {
		return false
	}

	return ident.Name == "True"
}

// updateRuleDeps updates the dependencies of a build rule based on the imports of its sources
func (u *updater) updateRuleDeps(conf *config.Config, rule *edit.Rule, rules []*edit.Rule, packageFiles map[string]*GoFile) error {
	done := map[string]struct{}{}

	// If the rule operates on non-go source files (e.g. *.proto for proto_library) then we should skip updating
	// it as we can't determine its deps from sources this way.
	if rule.Kind.NonGoSources {
		return nil
	}

	srcs, targetFiles, err := u.allSources(conf, rule, packageFiles)
	if err != nil {
		return err
	}

	label := edit.BuildTarget(rule.Name(), rule.Dir, "")

	deps := map[string]struct{}{}
	for _, src := range srcs {
		f := targetFiles[src]
		if f == nil {
			rule.RemoveSrc(src) // The src doesn't exist so remove it from the list of srcs
			continue
		}
		for _, i := range f.Imports {
			if _, ok := done[i]; ok {
				continue
			}
			done[i] = struct{}{}

			// If the dep is provided by the kind (i.e. the build def adds it) then skip this import

			dep, err := u.resolveImport(conf, i)
			if err != nil {
				log.Warningf("couldn't resolve %q for %v: %v", i, rule.Label(), err)
				continue
			}
			if dep == "" {
				continue
			}
			if rule.Kind.IsProvided(dep) {
				continue
			}

			dep = shorten(rule.Dir, dep)

			if _, ok := deps[dep]; !ok {
				deps[dep] = struct{}{}
			}
		}
	}

	// Add any libraries for the same package as us
	if rule.Kind.Type == kinds.Test && !isExternal(rule) {
		pkgName, err := u.rulePkg(conf, packageFiles, rule)
		if err != nil {
			return err
		}

		for _, libRule := range rules {
			if libRule.Kind.Type == kinds.Test {
				continue
			}
			libPkgName, err := u.rulePkg(conf, packageFiles, libRule)
			if err != nil {
				return err
			}

			if libPkgName != pkgName {
				continue
			}

			t := libRule.LocalLabel()
			if _, ok := deps[t]; !ok {
				deps[t] = struct{}{}
			}
		}
	}

	depSlice := make([]string, 0, len(deps))
	for dep := range deps {
		u.graph.EnsureVisibility(label, dep)
		depSlice = append(depSlice, dep)
	}

	rule.SetOrDeleteAttr("deps", depSlice)

	return nil
}

// allJSSources calculates the sources for a TS/JS target.
func (u *updater) allJSSources(conf *config.Config, r *edit.Rule, sourceMap map[string]*JSFile) (passedSources []string, jsFiles map[string]*JSFile, err error) {
	srcs, err := u.eval.BuildSources(conf.GetPlzPath(), r.Dir, r.Rule, r.SrcsAttr())
	if err != nil {
		return nil, nil, err
	}

	sources := make(map[string]*JSFile, len(srcs))
	for _, src := range srcs {
		if file, ok := sourceMap[src]; ok {
			sources[src] = file
			continue
		}

		// Handle generated sources in plz-out/gen
		f, skip, err := importJSFile(".", src)
		if err != nil {
			continue
		}
		if skip {
			continue
		}
		sources[src] = f
	}
	return srcs, sources, nil
}

// updateJSRuleDeps updates the dependencies of a TS/JS build rule based on the imports of its sources
func (u *updater) updateJSRuleDeps(conf *config.Config, rule *edit.Rule, rules []*edit.Rule, packageFiles map[string]*JSFile) error {
	done := map[string]struct{}{}

	// Only process ts_library and remix_bundle rules
	if rule.Kind.Name != "ts_library" && rule.Kind.Name != "remix_bundle" {
		return nil
	}

	srcs, targetFiles, err := u.allJSSources(conf, rule, packageFiles)
	if err != nil {
		return err
	}

	label := edit.BuildTarget(rule.Name(), rule.Dir, "")

	deps := map[string]struct{}{}

	for _, src := range srcs {
		f := targetFiles[src]
		if f == nil {
			log.Debugf("Removing %s", src)
			rule.RemoveSrc(src) // The src doesn't exist so remove it from the list of srcs
			continue
		}
		log.Debugf("updateJSRuleDeps: resolving imports for file: %s", src)
		for _, i := range f.Imports {
			log.Debugf("updateJSRuleDeps: resolving import: %v", i)
			if _, ok := done[i]; ok {
				continue
			}
			done[i] = struct{}{}

			// Skip built-in Node.js modules, npm: imports, and empty paths
			if strings.HasPrefix(i, "node:") || strings.HasPrefix(i, "npm:") || i == "" {
				continue
			}

			// Handle relative imports specially - they need to be resolved within the package
			if strings.HasPrefix(i, ".") || strings.HasPrefix(i, "/") {
				// Try to resolve local package
				relativePath := filepath.Join(rule.Dir, i)
				// Normalize the path
				relativePath = filepath.Clean(relativePath)

				// Check if there's a ts_library or remix_bundle rule in that directory
				for _, otherRule := range rules {
					if (otherRule.Kind.Name == "ts_library" || otherRule.Kind.Name == "remix_bundle") && otherRule.Dir == relativePath {
						dep := edit.BuildTarget(otherRule.Name(), relativePath, "")
						dep = shorten(rule.Dir, dep)
						if _, ok := deps[dep]; !ok {
							deps[dep] = struct{}{}
						}
						break
					}
				}
				continue
			}

			// Use our specialized JS import resolver that handles tsconfig.json path mappings
			// and the special @/ syntax for internal packages
			dep, local, skip := ResolveJSImport(i, rule.Dir)
			if skip {
				continue
			}

			if local {
				t, err := u.localDep(dep)
				if err != nil {
					return err
				}
				if t == "" {
					return fmt.Errorf("Could not find build target for %v", dep)
				}
			}

			dep = shorten(rule.Dir, dep)
			if _, ok := deps[dep]; !ok {
				deps[dep] = struct{}{}
			}
		}
	}

	depSlice := make([]string, 0, len(deps))
	for dep := range deps {
		u.graph.EnsureVisibility(label, dep)
		depSlice = append(depSlice, dep)
	}

	log.Debugf("Setting deps for %v to %v", rule.Name(), deps)

	rule.SetOrDeleteAttr("deps", depSlice)

	return nil
}

// shorten will shorten lables to the local package
func shorten(pkg, label string) string {
	if strings.HasPrefix(label, "///") || strings.HasPrefix(label, "@") {
		return label
	}

	return labels.Shorten(label, pkg)
}

// readRulesFromFile reads the existing build rules from the BUILD file
func (u *updater) readRulesFromFile(conf *config.Config, file *build.File, pkgDir string) ([]*edit.Rule, map[string]*build.Rule) {
	ruleExprs := file.Rules("")
	rules := make([]*edit.Rule, 0, len(ruleExprs))
	calls := map[string]*build.Rule{}

	for _, expr := range ruleExprs {
		kind := conf.GetKind(expr.Kind())
		if kind == nil {
			continue
		}
		rule := edit.NewRule(expr, kind, pkgDir)
		rules = append(rules, rule)
		calls[rule.Name()] = expr
	}

	return rules, calls
}

// updateDeps updates the existing rules and creates any new rules in the BUILD file
func (u *updater) updateDeps(conf *config.Config, file *build.File, ruleExprs map[string]*build.Rule, rules []*edit.Rule, sources map[string]*GoFile) error {
	for _, rule := range rules {
		if rule.Kind.Language != kinds.Go {
			continue
		}
		if _, ok := ruleExprs[rule.Name()]; !ok {
			file.Stmt = append(file.Stmt, rule.Call)
		}
		if err := u.updateRuleDeps(conf, rule, rules, sources); err != nil {
			return err
		}
	}
	return nil
}

// updateJSDeps updates dependencies for JavaScript/TypeScript rules
func (u *updater) updateJSDeps(conf *config.Config, file *build.File, ruleExprs map[string]*build.Rule, rules []*edit.Rule, sources map[string]*JSFile) error {
	for _, rule := range rules {
		if rule.Kind.Language != kinds.JS {
			continue
		}
		if _, ok := ruleExprs[rule.Name()]; !ok {
			file.Stmt = append(file.Stmt, rule.Call)
		}

		ruleSrcs, err := u.eval.EvalGlobs(rule.Dir, rule.Rule, rule.SrcsAttr())
		if err != nil {
			return err
		}

		allSrcs := make(map[string]*JSFile, len(sources))
		maps.Copy(allSrcs, sources)

		for _, s := range ruleSrcs {
			if filepath.Ext(s) != ".ts" && filepath.Ext(s) != ".tsx" {
				continue
			}
			f, skip, err := importJSFile(rule.Dir, s)
			if err != nil {
				return err
			}
			if skip {
				continue
			}
			log.Debugf("Adding ruleSrc: %v, f: %+v", s, f)
			allSrcs[s] = f
		}

		if err := u.updateJSRuleDeps(conf, rule, rules, allSrcs); err != nil {
			return err
		}
	}
	return nil
}

// allocateSources allocates sources to rules. If there's no existing rule, a new rule will be created and returned
// from this function
func (u *updater) allocateSources(conf *config.Config, pkgDir string, sources map[string]*GoFile, rules []*edit.Rule) ([]*edit.Rule, error) {
	unallocated, err := u.unallocatedSources(sources, rules)
	if err != nil {
		return nil, err
	}

	var newRules []*edit.Rule
	for _, src := range unallocated {
		importedFile := sources[src]
		if importedFile == nil {
			continue // Something went wrong and we haven't imported the file don't try to allocate it
		}
		var rule *edit.Rule
		for _, r := range append(rules, newRules...) {
			if r.Kind.Type != importedFile.kindType() {
				continue
			}

			rulePkgName, err := u.rulePkg(conf, sources, r)
			if err != nil {
				return nil, fmt.Errorf("failed to determine package name for //%v:%v: %w", pkgDir, r.Name(), err)
			}

			// Find a rule that's for the same package and of the same kind (i.e. bin, lib, test)
			// NB: we return when we find the first one so if there are multiple options, we will pick one essentially at
			//     random.
			if rulePkgName == "" || rulePkgName == importedFile.Name {
				rule = r
				break
			}
		}
		if rule == nil {
			name := filepath.Base(pkgDir)
			kind := "go_library"
			if importedFile.IsTest() {
				name += "_test"
				kind = "go_test"
			}
			if importedFile.IsCmd() {
				kind = "go_binary"
				name = "main"
			}
			rule = edit.NewRule(edit.NewRuleExpr(kind, name), kinds.DefaultKinds[kind], pkgDir)
			if importedFile.IsExternal(filepath.Join(u.plzConf.ImportPath(), pkgDir)) {
				setExternal(rule)
			}
			newRules = append(newRules, rule)
		}

		rule.AddSrc(src)
	}
	return newRules, nil
}

// allocateJSSources allocates JS/TS sources to rules, creating new rules as necessary
func (u *updater) allocateJSSources(conf *config.Config, pkgDir string, sources map[string]*JSFile, rules []*edit.Rule) ([]*edit.Rule, error) {
	unallocated, err := u.unallocatedJSSources(sources, rules)
	if err != nil {
		return nil, err
	}

	// Check if there are any JS/TS files to allocate
	if len(unallocated) == 0 {
		return nil, nil
	}

	// First, check if there are any existing ts_library or remix_bundle rules we can add to
	var jsRule *edit.Rule
	for _, r := range rules {
		if r.Kind.Name == "ts_library" || r.Kind.Name == "remix_bundle" {
			jsRule = r
			break
		}
	}

	log.Debugf("located rule: %v", jsRule)

	// If no existing rule found, create a new one
	if jsRule == nil {
		name := filepath.Base(pkgDir)
		// Default to ts_library
		kind := "ts_library"

		// Look for common JS framework patterns to determine the kind
		for _, src := range unallocated {
			fileName := filepath.Base(src)
			// If we find app.jsx or similar, use remix_bundle
			if strings.HasPrefix(fileName, "app.") || strings.HasPrefix(fileName, "entry.client.") || strings.HasPrefix(fileName, "entry.server.") {
				kind = "remix_bundle"
				break
			}
		}

		jsRule = edit.NewRule(edit.NewRuleExpr(kind, name), kinds.DefaultKinds[kind], pkgDir)

		// Add the rule to the list of new rules
		var newRules []*edit.Rule
		newRules = append(newRules, jsRule)

		// Add all unallocated JS/TS files to this rule
		for _, src := range unallocated {
			jsRule.AddSrc(src)
		}

		return newRules, nil
	}

	// Add unallocated sources to the existing rule
	log.Debugf("unallocated: %v", unallocated)
	for _, src := range unallocated {
		jsRule.AddSrc(src)
	}

	return nil, nil
}

// rulePkg checks the first source it finds for a rule and returns the name from the "package name" directive at the top
// of the file
func (u *updater) rulePkg(conf *config.Config, srcs map[string]*GoFile, rule *edit.Rule) (string, error) {
	// This is a safe bet if we can't use the source files to figure this out.
	if rule.Kind.NonGoSources {
		return rule.Name(), nil
	}

	ss, srcs, err := u.allSources(conf, rule, srcs)
	if err != nil {
		return "", err
	}

	for _, s := range ss {
		if src, ok := srcs[s]; ok {
			return src.Name, nil
		}
	}

	return "", nil
}

// unallocatedSources returns all the sources that don't already belong to a rule
func (u *updater) unallocatedSources(srcs map[string]*GoFile, rules []*edit.Rule) ([]string, error) {
	var ret []string
	for src := range srcs {
		found := false
		for _, rule := range rules {
			if found {
				break
			}

			ruleSrcs, err := u.eval.EvalGlobs(rule.Dir, rule.Rule, rule.SrcsAttr())
			if err != nil {
				return nil, err
			}
			for _, s := range ruleSrcs {
				if s == src {
					found = true
					break
				}
			}
		}
		if !found {
			ret = append(ret, src)
		}
	}
	return ret, nil
}

// unallocatedJSSources returns all the JS/TS sources that don't already belong to a rule
func (u *updater) unallocatedJSSources(srcs map[string]*JSFile, rules []*edit.Rule) ([]string, error) {
	var ret []string
	for src := range srcs {
		found := false
		for _, rule := range rules {
			if found {
				break
			}

			ruleSrcs, err := u.eval.EvalGlobs(rule.Dir, rule.Rule, rule.SrcsAttr())
			if err != nil {
				return nil, err
			}
			for _, s := range ruleSrcs {
				if s == src {
					found = true
					break
				}
			}
		}
		if !found {
			ret = append(ret, src)
		}
	}
	return ret, nil
}
