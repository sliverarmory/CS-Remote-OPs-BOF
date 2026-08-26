package extensions

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loadCSRemoteOpsCommand(t *testing.T, relativePath string) (*ExtensionManifest, *ExtCommand) {
	t.Helper()
	repo := os.Getenv("CS_REMOTE_OPS_REPO")
	if repo == "" {
		t.Fatal("CS_REMOTE_OPS_REPO is not set")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(repo, relativePath))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseExtensionManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.ExtCommand) != 1 {
		t.Fatalf("commands=%d, want 1", len(manifest.ExtCommand))
	}
	return manifest, manifest.ExtCommand[0]
}

func decodeCSRemoteOpsStrings(t *testing.T, packed []byte) []string {
	t.Helper()
	if len(packed) < 4 {
		t.Fatalf("packed buffer is only %d bytes", len(packed))
	}
	declared := int(binary.LittleEndian.Uint32(packed[:4]))
	body := packed[4:]
	if declared != len(body) {
		t.Fatalf("outer length=%d, body=%d", declared, len(body))
	}

	values := make([]string, 0, 9)
	for len(body) > 0 {
		if len(body) < 4 {
			t.Fatalf("truncated string length: %d bytes remain", len(body))
		}
		length := int(binary.LittleEndian.Uint32(body[:4]))
		body = body[4:]
		if length < 1 || length > len(body) || body[length-1] != 0 {
			t.Fatalf("invalid packed string length=%d remaining=%d", length, len(body))
		}
		values = append(values, string(body[:length-1]))
		body = body[length:]
	}
	return values
}

func TestCSRemoteOpsPackedABI(t *testing.T) {
	t.Run("lastpass", func(t *testing.T) {
		manifest, command := loadCSRemoteOpsCommand(t, "src/Remote/lastpass/extension.json")
		if manifest.PackageName != "remote-lastpass" || command.CommandName != "remote-lastpass" {
			t.Fatalf("identity=%q/%q", manifest.PackageName, command.CommandName)
		}
		if command.Entrypoint != "sliver" {
			t.Fatalf("entrypoint=%q", command.Entrypoint)
		}
		if command.BOFExecutor != "" || command.DependsOn != "coff-loader" {
			t.Fatalf("unexpected execution routing bof_executor=%q depends_on=%q", command.BOFExecutor, command.DependsOn)
		}
		if len(command.Arguments) != 1 || command.Arguments[0].Name != "pid" || command.Arguments[0].Type != "integer" {
			t.Fatalf("unexpected arguments: %#v", command.Arguments)
		}

		packed, err := ParseFlagArgumentsToBuffer(nil, []string{"-pid=1234"}, "", command)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0x04, 0x00, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00}
		if !reflect.DeepEqual(packed, want) {
			t.Fatalf("packed=% x, want=% x", packed, want)
		}
	})

	manifest, command := loadCSRemoteOpsCommand(t, "src/Remote/ghost_task/extension.json")
	if manifest.PackageName != "remote-ghost_task" || command.CommandName != "remote-ghost_task" {
		t.Fatalf("identity=%q/%q", manifest.PackageName, command.CommandName)
	}
	if command.Entrypoint != "sliver" {
		t.Fatalf("entrypoint=%q", command.Entrypoint)
	}
	if command.BOFExecutor != "" || command.DependsOn != "coff-loader" {
		t.Fatalf("unexpected execution routing bof_executor=%q depends_on=%q", command.BOFExecutor, command.DependsOn)
	}
	wantArgumentNames := []string{
		"computer-name", "operation", "task-name", "program", "program-arguments",
		"username", "schedule-type", "time", "days",
	}
	if len(command.Arguments) != len(wantArgumentNames) {
		t.Fatalf("arguments=%d, want %d", len(command.Arguments), len(wantArgumentNames))
	}
	for index, wantName := range wantArgumentNames {
		if command.Arguments[index].Name != wantName || command.Arguments[index].Type != "string" {
			t.Fatalf("argument[%d]=%q/%q", index, command.Arguments[index].Name, command.Arguments[index].Type)
		}
	}

	testCases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "delete",
			args: []string{"-computer-name=localhost", "-operation=delete", "-task-name=demo"},
			want: []string{"localhost", "delete", "demo", "", "", "", "", "", ""},
		},
		{
			name: "logon",
			args: []string{"-computer-name=localhost", "-operation=add", "-task-name=demo", "-program=cmd.exe", "-program-arguments=/c whoami", `-username=LAB\Administrator`, "-schedule-type=logon"},
			want: []string{"localhost", "add", "demo", "cmd.exe", "/c whoami", `LAB\Administrator`, "logon", "", ""},
		},
		{
			name: "second",
			args: []string{"-computer-name=localhost", "-operation=add", "-task-name=demo", "-program=cmd.exe", "-program-arguments=/c whoami", `-username=LAB\Administrator`, "-schedule-type=second", "-time=30"},
			want: []string{"localhost", "add", "demo", "cmd.exe", "/c whoami", `LAB\Administrator`, "second", "30", ""},
		},
		{
			name: "daily",
			args: []string{"-computer-name=localhost", "-operation=add", "-task-name=demo", "-program=cmd.exe", "-program-arguments=/c whoami", `-username=LAB\Administrator`, "-schedule-type=daily", "-time=20:37"},
			want: []string{"localhost", "add", "demo", "cmd.exe", "/c whoami", `LAB\Administrator`, "daily", "20:37", ""},
		},
		{
			name: "weekly",
			args: []string{"-days=monday,thursday", "-time=14:12", `-username=LAB\Administrator`, "-task-name=demo", "-operation=add", "-program-arguments=/c whoami", "-computer-name=localhost", "-schedule-type=weekly", "-program=cmd.exe"},
			want: []string{"localhost", "add", "demo", "cmd.exe", "/c whoami", `LAB\Administrator`, "weekly", "14:12", "monday,thursday"},
		},
	}

	for _, testCase := range testCases {
		t.Run("ghost_"+testCase.name, func(t *testing.T) {
			packed, err := ParseFlagArgumentsToBuffer(nil, testCase.args, "", command)
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeCSRemoteOpsStrings(t, packed); !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("decoded=%q, want=%q", got, testCase.want)
			}
		})
	}
}
