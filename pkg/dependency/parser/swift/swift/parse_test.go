package swift

import (
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		// docker run -it --rm swift@sha256:3c62ac97506ecf19ca15e4db57d7930e6a71559b23b19aa57e13d380133a54db
		// mkdir app && cd app
		// swift package init
		// ## add new deps: ##
		// sed -i 's/"1.0.0")/"1.0.0")\n.package(url: "https:\/\/github.com\/ReactiveCocoa\/ReactiveSwift", from: "7.0.0"),\n.package(url: "https:\/\/github.com\/Quick\/Nimble", .exact("9.2.1"))/' Package.swift
		// swift package update
		{
			name:      "happy path v1",
			inputFile: "testdata/happy-v1-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []ftypes.Location{{StartLine: 4, EndLine: 12}},
				},
				{
					ID:        "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
					Name:      "github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []ftypes.Location{{StartLine: 13, EndLine: 21}},
				},
			},
		},
		{
			name:      "happy path v2",
			inputFile: "testdata/happy-v2-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []ftypes.Location{{StartLine: 21, EndLine: 29}},
				},
				{
					ID:        "github.com/Quick/Quick@7.2.0",
					Name:      "github.com/Quick/Quick",
					Version:   "7.2.0",
					Locations: []ftypes.Location{{StartLine: 30, EndLine: 38}},
				},
				{
					ID:        "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
					Name:      "github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []ftypes.Location{{StartLine: 39, EndLine: 47}},
				},
				{
					ID:        "github.com/element-hq/swift-ogg@0.0.1",
					Name:      "github.com/element-hq/swift-ogg",
					Version:   "0.0.1",
					Locations: []ftypes.Location{{StartLine: 48, EndLine: 56}},
				},
				{
					ID:        "github.com/mattgallagher/CwlCatchException@2.1.2",
					Name:      "github.com/mattgallagher/CwlCatchException",
					Version:   "2.1.2",
					Locations: []ftypes.Location{{StartLine: 3, EndLine: 11}},
				},
				{
					ID:        "github.com/mattgallagher/CwlPreconditionTesting@2.1.2",
					Name:      "github.com/mattgallagher/CwlPreconditionTesting",
					Version:   "2.1.2",
					Locations: []ftypes.Location{{StartLine: 12, EndLine: 20}},
				},
			},
		},
		{
			// Xcode and Swift Package Manager write a location as it was typed, so one
			// or more trailing slashes are kept, as in `.../Sparkle/` or `.../swift-numerics//`.
			name:      "location with trailing slashes",
			inputFile: "testdata/trailing-slash-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/apple/swift-numerics@1.1.1",
					Name:      "github.com/apple/swift-numerics",
					Version:   "1.1.1",
					Locations: []ftypes.Location{{StartLine: 12, EndLine: 20}},
				},
				{
					ID:        "github.com/sparkle-project/Sparkle@2.9.6",
					Name:      "github.com/sparkle-project/Sparkle",
					Version:   "2.9.6",
					Locations: []ftypes.Location{{StartLine: 3, EndLine: 11}},
				},
			},
		},
		{
			// v1 stores the URL in `repositoryURL`. Same trailing-slash and `.git` shapes as v2.
			name:      "v1 repositoryURL with trailing slashes and .git",
			inputFile: "testdata/trailing-slash-v1-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []ftypes.Location{{StartLine: 4, EndLine: 12}},
				},
				{
					ID:        "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
					Name:      "github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []ftypes.Location{{StartLine: 31, EndLine: 39}},
				},
				{
					ID:        "github.com/apple/swift-numerics@1.1.1",
					Name:      "github.com/apple/swift-numerics",
					Version:   "1.1.1",
					Locations: []ftypes.Location{{StartLine: 22, EndLine: 30}},
				},
				{
					ID:        "github.com/sparkle-project/Sparkle@2.9.6",
					Name:      "github.com/sparkle-project/Sparkle",
					Version:   "2.9.6",
					Locations: []ftypes.Location{{StartLine: 13, EndLine: 21}},
				},
			},
		},
		{
			// v2 `location` where `.git` and trailing slashes are combined.
			name:      "v2 location with .git and trailing slashes",
			inputFile: "testdata/git-suffix-v2-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []ftypes.Location{{StartLine: 12, EndLine: 20}},
				},
				{
					ID:        "github.com/sparkle-project/Sparkle@2.9.6",
					Name:      "github.com/sparkle-project/Sparkle",
					Version:   "2.9.6",
					Locations: []ftypes.Location{{StartLine: 3, EndLine: 11}},
				},
			},
		},
		{
			// v3 keeps v2 pins and adds originHash. `location` is still the URL.
			name:      "v3 location with trailing slashes and .git",
			inputFile: "testdata/trailing-slash-v3-Package.resolved",
			want: []ftypes.Package{
				{
					ID:        "github.com/apple/swift-numerics@1.1.1",
					Name:      "github.com/apple/swift-numerics",
					Version:   "1.1.1",
					Locations: []ftypes.Location{{StartLine: 13, EndLine: 21}},
				},
				{
					ID:        "github.com/sparkle-project/Sparkle@2.9.6",
					Name:      "github.com/sparkle-project/Sparkle",
					Version:   "2.9.6",
					Locations: []ftypes.Location{{StartLine: 4, EndLine: 12}},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty-Package.resolved",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			gotPkgs, _, err := parser.Parse(t.Context(), f)
			require.NoError(t, err)
			assert.Equal(t, tt.want, gotPkgs)

			for _, pkg := range gotPkgs {
				got, err := purl.New(ftypes.Swift, types.Metadata{}, pkg)
				require.NoError(t, err)
				require.NotEmpty(t, got.Name)
				assert.Equal(t, "pkg:swift/"+pkg.Name+"@"+pkg.Version, got.String())
				_, err = packageurl.FromString(got.String())
				require.NoError(t, err)
			}
		})
	}
}

func Test_pkgName(t *testing.T) {
	const want = "github.com/sparkle-project/Sparkle"
	tests := []struct {
		name        string
		lockVersion int
		pin         Pin
		want        string
	}{
		{
			name:        "v1 single trailing slash",
			lockVersion: 1,
			pin:         Pin{RepositoryURL: "https://github.com/sparkle-project/Sparkle/"},
			want:        want,
		},
		{
			name:        "v1 multiple trailing slashes",
			lockVersion: 1,
			pin:         Pin{RepositoryURL: "https://github.com/sparkle-project/Sparkle//"},
			want:        want,
		},
		{
			name:        "v1 three trailing slashes",
			lockVersion: 1,
			pin:         Pin{RepositoryURL: "https://github.com/sparkle-project/Sparkle///"},
			want:        want,
		},
		{
			name:        "v2 single trailing slash",
			lockVersion: 2,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle/"},
			want:        want,
		},
		{
			name:        "v2 multiple trailing slashes",
			lockVersion: 2,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle//"},
			want:        want,
		},
		{
			name:        "v3 multiple trailing slashes",
			lockVersion: 3,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle//"},
			want:        want,
		},
		{
			name:        "v2 .git suffix",
			lockVersion: 2,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle.git"},
			want:        want,
		},
		{
			name:        "v2 .git suffix and one trailing slash",
			lockVersion: 2,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle.git/"},
			want:        want,
		},
		{
			name:        "v1 .git suffix and multiple trailing slashes",
			lockVersion: 1,
			pin:         Pin{RepositoryURL: "https://github.com/sparkle-project/Sparkle.git//"},
			want:        want,
		},
		{
			name:        "v1 slash before .git",
			lockVersion: 1,
			pin:         Pin{RepositoryURL: "https://github.com/sparkle-project/Sparkle/.git"},
			want:        want,
		},
		{
			name:        "v2 slash before .git and a trailing slash",
			lockVersion: 2,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle/.git/"},
			want:        want,
		},
		{
			name:        "v3 slash before .git and multiple trailing slashes",
			lockVersion: 3,
			pin:         Pin{Loc: "https://github.com/sparkle-project/Sparkle/.git//"},
			want:        want,
		},
		{
			name:        "v1 uses repositoryURL, not location",
			lockVersion: 1,
			pin: Pin{
				RepositoryURL: "https://github.com/sparkle-project/Sparkle/",
				Loc:           "https://github.com/wrong/Wrong//",
			},
			want: want,
		},
		{
			name:        "v2 uses location, not repositoryURL",
			lockVersion: 2,
			pin: Pin{
				RepositoryURL: "https://github.com/wrong/Wrong.git/",
				Loc:           "https://github.com/sparkle-project/Sparkle//",
			},
			want: want,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pkgName(tt.pin, tt.lockVersion))
		})
	}
}
