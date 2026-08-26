package extensions

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"

	"github.com/bishopfox/sliver/util"
)

func TestCSRemoteOpsArchivesInstallable(t *testing.T) {
	repoRoot := os.Getenv("CS_REMOTE_OPS_REPO")
	if repoRoot == "" {
		t.Fatal("CS_REMOTE_OPS_REPO is required")
	}

	inventory, err := os.Open(filepath.Join(repoRoot, "armory-package-inventory.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()

	scanner := bufio.NewScanner(inventory)
	packageCount := 0
	for scanner.Scan() {
		packageName := scanner.Text()
		packageCount++
		t.Run(packageName, func(t *testing.T) {
			archivePath := filepath.Join(repoRoot, "packages", packageName+".tar.gz")
			manifestData, err := util.ReadFileFromTarGz(archivePath, "./"+ManifestFileName)
			if err != nil {
				t.Fatal(err)
			}
			if len(manifestData) == 0 {
				t.Fatalf("%s is missing ./extension.json", archivePath)
			}

			manifest, err := ParseExtensionManifest(manifestData)
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range manifest.ExtCommand {
				for _, artifact := range command.Files {
					memberPath := "." + filepath.ToSlash(artifact.Path)
					data, err := util.ReadFileFromTarGz(archivePath, memberPath)
					if err != nil {
						t.Fatalf("read %s: %v", memberPath, err)
					}
					if len(data) == 0 {
						t.Fatalf("%s is missing or empty", memberPath)
					}
				}
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if packageCount != 51 {
		t.Fatalf("tested %d packages, want 51", packageCount)
	}
}
