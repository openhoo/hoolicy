package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/repository"
)

// OutputPaths preflights every decision artifact before evaluation or signing
// can publish a file. Ignored policy inputs remain protected even though they
// are excluded from the ordinary repository snapshot.
func OutputPaths(project *config.Project, outputs []string) ([]string, error) {
	protected := []string{project.Path}
	for _, relative := range []string{config.DefaultLockfile, project.Waivers, project.Baseline, project.Trust, project.Evidence} {
		if relative != "" {
			protected = append(protected, filepath.Join(project.Root, filepath.FromSlash(relative)))
		}
	}
	policy, err := LoadPolicy(project)
	if err != nil {
		return nil, err
	}
	for _, spec := range policy.External {
		protected = append(protected, filepath.Join(project.Root, filepath.FromSlash(spec.Path)))
	}
	packRoots := []string{}
	for _, pack := range project.Packs {
		path := pack.Path
		if pack.Git != "" || pack.OCI != "" {
			path = filepath.Join(".hoolicy", "vendor", pack.Name)
		}
		absolute := filepath.Join(project.Root, filepath.FromSlash(path))
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		packRoots = append(packRoots, filepath.Clean(absolute))
	}
	canonical := make([]string, 0, len(outputs))
	for _, output := range outputs {
		absolute, err := repository.ArtifactOutputPath(project.Root, output)
		if err != nil {
			return nil, fmt.Errorf("evidence output: %w", err)
		}
		if filepath.Base(absolute) == ".gitignore" {
			return nil, fmt.Errorf("evidence output %s would overwrite Git ignore policy", output)
		}
		for _, input := range protected {
			resolved, err := repository.CanonicalOutputPath(input)
			if err != nil {
				return nil, err
			}
			if sameOutputPath(absolute, resolved) {
				return nil, fmt.Errorf("evidence output %s would overwrite a policy input", output)
			}
		}
		for _, packRoot := range packRoots {
			inside, err := repository.PathWithin(packRoot, absolute)
			if err != nil {
				return nil, err
			}
			if inside {
				return nil, fmt.Errorf("evidence output %s would overwrite policy pack content", output)
			}
		}
		for _, existing := range canonical {
			insideExisting, err := repository.PathWithin(existing, absolute)
			if err != nil {
				return nil, err
			}
			containsExisting, err := repository.PathWithin(absolute, existing)
			if err != nil {
				return nil, err
			}
			if sameOutputPath(existing, absolute) || insideExisting || containsExisting {
				return nil, fmt.Errorf("evidence artifact outputs must use distinct, nonoverlapping paths: %s", output)
			}
		}
		canonical = append(canonical, absolute)
	}
	return canonical, nil
}

func sameOutputPath(left, right string) bool {
	if left == right || (runtime.GOOS == "windows" || runtime.GOOS == "darwin") && strings.EqualFold(left, right) {
		return true
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}
