package graph

import (
	"bytes"
	"testing"

	"github.com/please-build/buildtools/build"
	"github.com/please-build/buildtools/labels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/please-build/puku/config"
	"github.com/please-build/puku/edit"
	"github.com/please-build/puku/options"
)

func TestLoadBuildFile(t *testing.T) {
	g := New([]string{"BUILD_FILE", "BUILD_FILE.plz"}, options.TestOptions)

	f, err := g.LoadFile("test_project")
	require.NoError(t, err)

	libs := f.Rules("go_library")
	require.Len(t, libs, 1)

	f, err = g.LoadFile("test_project/foo")
	require.NoError(t, err)

	libs = f.Rules("go_library")
	require.Len(t, libs, 1)

	f, err = g.LoadFile("test_project/foo/bar")
	require.NoError(t, err)
	assert.Equal(t, "test_project/foo/bar/BUILD_FILE", f.Path)
}

func TestEnsureVisibility(t *testing.T) {
	g := New(nil, options.TestOptions).WithExperimentalDirs("exp", "experimental")

	foo, err := build.ParseBuild("foo/BUILD", []byte(`
go_library(
	name = "foo",
	srcs = ["main.go"],
)
`))
	require.NoError(t, err)

	bar, err := build.ParseBuild("bar/BUILD", []byte(`
go_library(
	name = "bar",
	srcs = ["bar.go"],
	deps = ["//foo"],
)
`))
	require.NoError(t, err)

	experimental, err := build.ParseBuild("experimental/BUILD", []byte(`
go_library(
	name = "experimental",
	srcs = ["experimental.go"],
	deps = ["//foo"],
)
`))
	require.NoError(t, err)

	g.files["foo"] = foo
	g.files["bar"] = bar
	g.files["experimental"] = experimental

	g.EnsureVisibility("//bar", "//foo")
	g.EnsureVisibility("//bar", "///github.com//foo")          // skipped - target in subrepo
	g.EnsureVisibility("//bar", ":foo")                        // skipped - local dep
	g.EnsureVisibility("//bar:bar_test", "//bar")              // skipped - also local
	g.EnsureVisibility("//experimental:experimental", "//foo") // skipped - experimental
	require.Len(t, g.deps, 1)
	require.Equal(t, g.deps[0], &Dependency{
		From: labels.Parse("//bar"),
		To:   labels.Parse("//foo"),
	})

	bs := new(bytes.Buffer)
	err = g.FormatFilesWithWriter(bs, "text")
	require.NoError(t, err)

	fooT := edit.FindTargetByName(g.files["foo"], "foo")
	assert.ElementsMatch(t, []string{"//bar:all"}, fooT.AttrStrings("visibility"))

	require.Contains(t, bs.String(), `visibility = ["//bar:all"]`)
}

func TestDefaultVisibility(t *testing.T) {
	conf := &config.Config{
		LibKinds: map[string]*config.KindConfig{
			"my_go_library": {
				DefaultVisibility: []string{"//bar/..."},
			},
		},
	}

	foo, err := build.ParseBuild("foo/BUILD", []byte(`
my_go_library(
	name = "foo",
	srcs = ["main.go"],
)
`))
	require.NoError(t, err)

	bar, err := build.ParseBuild("bar/BUILD", []byte(`
package(default_visibility = ["//baz/..."])

go_library(
	name = "bar",
	srcs = ["bar.go"],
	deps = ["//foo"],
)
`))
	require.NoError(t, err)

	baz, err := build.ParseBuild("baz/BUILD", []byte(`
package(default_visibility = ["//fizz/..."])

go_library(
	name = "baz",
	srcs = ["baz.go"],
	deps = ["//foo"],
	visibility = ["//foo/..."],
)
`))
	require.NoError(t, err)

	fizz, err := build.ParseBuild("baz/BUILD", []byte(`
go_library(
	name = "fizz",
	srcs = ["fizz.go"],
	deps = ["//baz"],
)
`))
	require.NoError(t, err)

	g := New(nil, options.TestOptions)
	g.files["foo"] = foo
	g.files["bar"] = bar
	g.files["baz"] = baz
	g.files["fizz"] = fizz

	g.EnsureVisibility("//bar", "//foo")  // Handled by kinds default visibility
	g.EnsureVisibility("//baz", "//bar")  // Handled by package default visibility
	g.EnsureVisibility("//fizz", "//baz") // Needs update as package visibility is overridden by visibility arg

	for _, dep := range g.deps {
		require.NoError(t, g.ensureVisibility(conf, dep))
	}

	assert.Empty(t, edit.FindTargetByName(foo, "foo").AttrStrings("visibility"))
	assert.Empty(t, edit.FindTargetByName(bar, "bar").AttrStrings("visibility"))
	assert.Empty(t, edit.FindTargetByName(fizz, "fizz").AttrStrings("visibility"))

	// This was overridden even though we set the package visibility because the rule set visibility explicitly
	assert.ElementsMatch(t,
		[]string{"//foo/...", "//fizz:all"},
		edit.FindTargetByName(baz, "baz").AttrStrings("visibility"),
	)
}

func TestCheckVisibility(t *testing.T) {
	assert := assert.New(t)
	for _, test := range []struct {
		description string
		label       string
		visibility  []string
		expected    bool
	}{
		{
			description: "Exact match",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/bar:baz"},
			expected:    true,
		},
		{
			description: "Matches :all pseudo-label for same package",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/bar:all"},
			expected:    true,
		},
		{
			description: "Doesn't match :all pseudo-label for different package",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/baz:all"},
			expected:    false,
		},
		{
			description: "Matches PUBLIC pseudo-label",
			label:       "//foo/bar:baz",
			visibility:  []string{"PUBLIC"},
			expected:    true,
		},
		{
			description: "Matches top-level package's wildcard",
			label:       "//foo/bar:baz",
			visibility:  []string{"//..."},
			expected:    true,
		},
		{
			description: "Matches top-level package's wildcard for top-level label",
			label:       "//:baz",
			visibility:  []string{"//..."},
			expected:    true,
		},
		{
			description: "Matches parent package's wildcard",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/..."},
			expected:    true,
		},
		{
			description: "Matches same package's wildcard",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/bar/..."},
			expected:    true,
		},
		{
			description: "Doesn't match child package's wildcard",
			label:       "//foo/bar:baz",
			visibility:  []string{"//foo/bar/buh/..."},
			expected:    false,
		},
		{
			description: "Doesn't match wildcard of a package with different parent",
			label:       "//foo/bar:baz",
			visibility:  []string{"//bar/..."},
			expected:    false,
		},
	} {
		label := labels.Parse(test.label)
		assert.Equal(test.expected, checkVisibility(label, test.visibility), test.description)
	}
}

func TestGetDefaultVisibilityFromFile(t *testing.T) {
	file, err := build.ParseBuild("test", []byte("package(default_visibility = [\"PUBLIC\"])"))
	require.NoError(t, err)

	assert.Equal(t, []string{"PUBLIC"}, getDefaultVisibility(file))
}
