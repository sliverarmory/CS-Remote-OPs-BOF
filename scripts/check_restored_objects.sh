#!/usr/bin/env bash

set -euo pipefail

REPOROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OBJDUMP_X64=${OBJDUMP_X64:-x86_64-w64-mingw32-objdump}
OBJDUMP_X86=${OBJDUMP_X86:-i686-w64-mingw32-objdump}

require_symbol() {
    local objdump=$1
    local object=$2
    local symbol=$3
    local symbols
    symbols=$("$objdump" -t "$object")
    if ! grep -E "\\(sec[[:space:]]+1\\).* ${symbol}$" <<<"$symbols" >/dev/null; then
        echo "ERROR: $object does not define required short entrypoint $symbol" >&2
        exit 1
    fi
}

require_relocation() {
    local objdump=$1
    local object=$2
    local symbol=$3
    local relocations
    relocations=$("$objdump" -r "$object")
    if ! grep -F "$symbol" <<<"$relocations" >/dev/null; then
        echo "ERROR: $object does not reference required cleanup import $symbol" >&2
        exit 1
    fi
}

for package_name in lastpass ghost_task; do
    x64_object="$REPOROOT/Remote/$package_name/$package_name.x64.o"
    x86_object="$REPOROOT/Remote/$package_name/$package_name.x86.o"
    require_symbol "$OBJDUMP_X64" "$x64_object" go
    require_symbol "$OBJDUMP_X64" "$x64_object" sliver
    require_symbol "$OBJDUMP_X86" "$x86_object" _go
    require_symbol "$OBJDUMP_X86" "$x86_object" _sliver
    require_symbol "$OBJDUMP_X86" "$x86_object" sliver
    x64_symbols=$("$OBJDUMP_X64" -t "$x64_object")
    x86_symbols=$("$OBJDUMP_X86" -t "$x86_object")
    if grep 'go_sliver' <<<"$x64_symbols" >/dev/null ||
       grep 'go_sliver' <<<"$x86_symbols" >/dev/null; then
        echo "ERROR: $package_name still exports the COFFLoader-incompatible long entrypoint" >&2
        exit 1
    fi
done

sc_failure_x86="$REPOROOT/Remote/sc_failure/sc_failure.x86.o"
if "$OBJDUMP_X86" -t "$sc_failure_x86" | grep -F 'chkstk' >/dev/null ||
   "$OBJDUMP_X86" -r "$sc_failure_x86" | grep -F 'chkstk' >/dev/null; then
    echo "ERROR: sc_failure x86 still contains an unsupported chkstk stack probe" >&2
    exit 1
fi

require_relocation "$OBJDUMP_X64" "$REPOROOT/Remote/ghost_task/ghost_task.x64.o" __imp_FreeLibrary
require_relocation "$OBJDUMP_X86" "$REPOROOT/Remote/ghost_task/ghost_task.x86.o" __imp__FreeLibrary@4

x64_memory=$(
    "$OBJDUMP_X64" -dr "$REPOROOT/Remote/lastpass/lastpass.x64.o" |
        sed -n '/<GetProcessMemory>:/,/^$/p'
)
x86_memory=$(
    "$OBJDUMP_X86" -dr "$REPOROOT/Remote/lastpass/lastpass.x86.o" |
        sed -n '/<_GetProcessMemory>:/,/^$/p'
)
printf '%s\n' "$x64_memory" | grep -Eq 'mov.*\$0x30,%r9d'
printf '%s\n' "$x64_memory" | grep -Eq 'cmp.*\$0x30,%rax'
printf '%s\n' "$x86_memory" | grep -Eq 'movl.*\$0x1c,0xc\(%esp\)'
printf '%s\n' "$x86_memory" | grep -Eq 'cmp.*\$0x1c,%eax'

x64_sliver=$(
    "$OBJDUMP_X64" -dr "$REPOROOT/Remote/lastpass/lastpass.x64.o" |
        sed -n '/<sliver>:/,/^$/p'
)
x86_sliver=$(
    "$OBJDUMP_X86" -dr "$REPOROOT/Remote/lastpass/lastpass.x86.o" |
        sed -n '/<_sliver>:/,/^$/p'
)
if [[ $(printf '%s\n' "$x64_sliver" | grep -Ec '\$0x22') -lt 2 ]] ||
   [[ $(printf '%s\n' "$x86_sliver" | grep -Ec '\$0x22') -lt 2 ]]; then
    echo "ERROR: LastPass Sliver EXIT record must allocate and emit exactly 34 bytes" >&2
    exit 1
fi

echo "[+] Restored BOF object safety checks passed"
