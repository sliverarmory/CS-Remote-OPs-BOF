//go:build windows && (386 || amd64)

package handlers

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/sliverarmory/reflektor/bof"
)

var csRemoteOpsLegacyBOFPackages = map[string]struct{}{
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

type csRemoteOpsArchiveFile struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Path string `json:"path"`
}

type csRemoteOpsArchiveCommand struct {
	CommandName string                   `json:"command_name"`
	BOFExecutor string                   `json:"bof_executor"`
	DependsOn   string                   `json:"depends_on"`
	Entrypoint  string                   `json:"entrypoint"`
	Files       []csRemoteOpsArchiveFile `json:"files"`
}

type csRemoteOpsArchiveManifest struct {
	csRemoteOpsArchiveCommand
	Commands []csRemoteOpsArchiveCommand `json:"commands"`
}

func TestCSRemoteOpsReflektorLoaderCompatibility(t *testing.T) {
	if runtime.GOOS != "windows" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "386") {
		t.Fatalf("test must run natively on windows/amd64 or windows/386, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	repoRoot := os.Getenv("CS_REMOTE_OPS_REPO")
	if repoRoot == "" {
		t.Fatal("CS_REMOTE_OPS_REPO is required")
	}
	inventory, err := os.Open(filepath.Join(repoRoot, "armory-package-inventory.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()

	// Legacy packages need Cobalt Strike host callbacks that Sliver does not
	// expose. A real Windows function address lets Reflektor finish relocation
	// validation without ever invoking one of those operational callbacks.
	hostCallbackAddress := syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcessId").Addr()
	if hostCallbackAddress == 0 {
		t.Fatal("host callback relocation fixture has a zero address")
	}

	packageCount := 0
	reflektorCount := 0
	coffLoaderCount := 0
	scanner := bufio.NewScanner(inventory)
	for scanner.Scan() {
		packageName := scanner.Text()
		packageCount++
		t.Run(packageName, func(t *testing.T) {
			archivePath := filepath.Join(repoRoot, "packages", packageName+".tar.gz")
			manifestData := readCSRemoteOpsArchiveMember(t, archivePath, "extension.json")
			command := decodeCSRemoteOpsArchiveCommand(t, manifestData)
			if command.CommandName != packageName {
				t.Fatalf("manifest command_name=%q, want inventory name %q", command.CommandName, packageName)
			}

			_, legacyCOFFLoader := csRemoteOpsLegacyBOFPackages[packageName]
			wantExecutor := "reflektor"
			if legacyCOFFLoader {
				wantExecutor = "coff-loader"
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

			artifact := selectCSRemoteOpsArchiveFile(t, command.Files)
			objectData := readCSRemoteOpsArchiveMember(t, archivePath, artifact.Path)
			loadOptions := csRemoteOpsBOFLoadOptions(command.Entrypoint)

			// ValidateImports runs after object/host parsing and exact entrypoint
			// selection, but before allocation, symbol lookup, or any native code.
			probeErr := errors.New("entrypoint and import probe complete")
			var imports []bof.Import
			probeOptions := loadOptions
			probeOptions.ValidateImports = func(input []bof.Import) error {
				imports = append([]bof.Import(nil), input...)
				return probeErr
			}
			probed, err := bof.LoadWithOptions(objectData, probeOptions)
			if probed != nil {
				_ = probed.Close()
				t.Fatal("import probe unexpectedly returned a loaded BOF")
			}
			if !errors.Is(err, probeErr) {
				t.Fatalf("entrypoint/import probe failed before policy callback: %v", err)
			}

			requiresHost := 0
			for _, imported := range imports {
				if imported.RequiresHost {
					requiresHost++
				}
			}
			if legacyCOFFLoader && requiresHost == 0 {
				t.Fatal("legacy COFFLoader package has no host-required imports")
			}
			if !legacyCOFFLoader && requiresHost != 0 {
				t.Fatalf("Reflektor package has %d host-required import(s)", requiresHost)
			}

			var loaded bofObject
			if legacyCOFFLoader {
				loadOptions.ResolveSymbol = func(imported bof.Import) (uintptr, bool, error) {
					if imported.RequiresHost {
						return hostCallbackAddress, true, nil
					}
					return 0, false, nil
				}
				loaded, err = bof.LoadWithOptions(objectData, loadOptions)
			} else {
				// This is the exact loader entry used by Sliver's built-in executor.
				// Deliberately close without calling Execute: these BOFs perform
				// credential access, injection, and other operational behavior.
				loaded, err = loadReflektorBOF(objectData, loadOptions)
			}
			if err != nil {
				t.Fatalf("load and relocate %s/%s without execution: %v", artifact.OS, artifact.Arch, err)
			}
			if err := loaded.Close(); err != nil {
				t.Fatalf("close relocated BOF: %v", err)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if packageCount != 51 || reflektorCount != 37 || coffLoaderCount != 14 {
		t.Fatalf(
			"validated packages=%d Reflektor=%d COFFLoader=%d, want 51/37/14",
			packageCount,
			reflektorCount,
			coffLoaderCount,
		)
	}
}

func csRemoteOpsBOFLoadOptions(entrypoint string) bof.LoadOptions {
	options := bof.LoadOptions{}
	if !isDefaultBOFEntryPoint(entrypoint) {
		options.EntryPoint = entrypoint
	}
	return options
}

func decodeCSRemoteOpsArchiveCommand(t *testing.T, data []byte) csRemoteOpsArchiveCommand {
	t.Helper()
	manifest := csRemoteOpsArchiveManifest{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Commands) == 0 {
		return manifest.csRemoteOpsArchiveCommand
	}
	if len(manifest.Commands) != 1 {
		t.Fatalf("manifest commands=%d, want 1", len(manifest.Commands))
	}
	return manifest.Commands[0]
}

func selectCSRemoteOpsArchiveFile(t *testing.T, files []csRemoteOpsArchiveFile) csRemoteOpsArchiveFile {
	t.Helper()
	selected := []csRemoteOpsArchiveFile{}
	for _, file := range files {
		if file.OS == runtime.GOOS && file.Arch == runtime.GOARCH {
			selected = append(selected, file)
		}
	}
	if len(selected) != 1 {
		t.Fatalf("matching artifacts for %s/%s=%d, want 1", runtime.GOOS, runtime.GOARCH, len(selected))
	}
	return selected[0]
}

func readCSRemoteOpsArchiveMember(t *testing.T, archivePath string, memberPath string) []byte {
	t.Helper()
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()

	wanted := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(memberPath)), "/")
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
		if name != wanted {
			continue
		}
		if !header.FileInfo().Mode().IsRegular() || header.Size <= 0 {
			t.Fatalf("archive member %q is not a non-empty regular file", memberPath)
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != header.Size {
			t.Fatalf("archive member %q size=%d, want %d", memberPath, len(data), header.Size)
		}
		return data
	}
	t.Fatal(fmt.Errorf("archive %s does not contain %s", archivePath, memberPath))
	return nil
}
