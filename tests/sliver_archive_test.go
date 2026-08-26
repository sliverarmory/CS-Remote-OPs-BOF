package extensions

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util"
)

var csRemoteOpsLegacyCOFFLoaderPackages = map[string]struct{}{
	"inject-clipboard":           {},
	"inject-conhost":             {},
	"inject-createremotethread":  {},
	"inject-ctray":               {},
	"inject-dde":                 {},
	"inject-kernelcallbacktable": {},
	"inject-ntcreatethread":      {},
	"inject-ntqueueapcthread":    {},
	"inject-setthreadcontext":    {},
	"inject-svcctrl":             {},
	"inject-tooltip":             {},
	"inject-uxsubclassinfo":      {},
	"remote-make_token_cert":     {},
	"remote-shspawnas":           {},
}

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
	reflektorCount := 0
	coffLoaderCount := 0
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
			if len(manifest.ExtCommand) != 1 {
				t.Fatalf("commands=%d, want 1", len(manifest.ExtCommand))
			}

			command := manifest.ExtCommand[0]
			_, legacyCOFFLoader := csRemoteOpsLegacyCOFFLoaderPackages[command.CommandName]
			wantExecutor := BOFExecutorReflektor
			wantMode := extensionExecutionReflektor
			if legacyCOFFLoader {
				wantExecutor = BOFExecutorCOFFLoader
				wantMode = extensionExecutionCOFFLoader
				coffLoaderCount++
			} else {
				reflektorCount++
			}
			if command.BOFExecutor != wantExecutor {
				t.Fatalf("bof_executor=%q, want %q", command.BOFExecutor, wantExecutor)
			}
			if command.DependsOn != "coff-loader" {
				t.Fatalf("depends_on=%q, want compatibility fallback %q", command.DependsOn, "coff-loader")
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

					root := t.TempDir()
					objectPath := filepath.Join(root, filepath.FromSlash(artifact.Path))
					if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(objectPath, data, 0o600); err != nil {
						t.Fatal(err)
					}
					fallbackMode, err := planExtensionExecution(command, objectPath, 0)
					if err != nil {
						t.Fatalf("plan compatibility fallback for %s/%s: %v", artifact.OS, artifact.Arch, err)
					}
					if fallbackMode != extensionExecutionCOFFLoader {
						t.Fatalf(
							"compatibility mode for %s/%s=%d, want COFFLoader mode %d",
							artifact.OS,
							artifact.Arch,
							fallbackMode,
							extensionExecutionCOFFLoader,
						)
					}
					mode, err := planExtensionExecution(command, objectPath, sliverpb.CapabilityBOFV1)
					if err != nil {
						t.Fatalf("plan %s/%s: %v", artifact.OS, artifact.Arch, err)
					}
					if mode != wantMode {
						t.Fatalf("execution mode for %s/%s=%d, want %d", artifact.OS, artifact.Arch, mode, wantMode)
					}
					if mode != extensionExecutionReflektor {
						continue
					}

					request, err := buildCallExtensionRequest(
						artifact.OS,
						artifact.Arch,
						mode,
						command,
						objectPath,
						command.Entrypoint,
						nil,
					)
					if err != nil {
						t.Fatalf("build Reflektor request for %s/%s: %v", artifact.OS, artifact.Arch, err)
					}
					digest := sha256.Sum256(data)
					if request.Name != hex.EncodeToString(digest[:]) {
						t.Fatalf("request name=%q, want object digest", request.Name)
					}
					if !request.IsBOF || !bytes.Equal(request.BOFData, data) {
						t.Fatal("Reflektor request does not carry the exact BOF object")
					}
					if request.Export != command.Entrypoint {
						t.Fatalf("request export=%q, want manifest entrypoint %q", request.Export, command.Entrypoint)
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
	if reflektorCount != 37 || coffLoaderCount != 14 {
		t.Fatalf("routing counts: Reflektor=%d COFFLoader=%d, want 37/14", reflektorCount, coffLoaderCount)
	}
}
