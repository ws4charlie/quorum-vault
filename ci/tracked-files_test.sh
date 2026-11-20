#!/usr/bin/env bash
# Test of ci/tracked-files.sh on fixtures in a scratch git repository: build outputs (found by magic bytes, whatever the name) and large files fail; a PNG,
# text, a Java class and a documented large file pass.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
r="$tmp/r"; git init -q "$r"; : > "$tmp/n"; : > "$tmp/f"
export QV_TRACKED_EXCEPTIONS="$tmp/exc"; : > "$QV_TRACKED_EXCEPTIONS"
# t <ok|fail> <description> <file> <hex bytes> [<total size>]  (the rest is zero bytes)
t() {
  local want="$1" desc="$2" file="$3" hexs="$4" size="${5:-0}" out rc
  mkdir -p "$(dirname "$r/$file")"
  { printf '%b' "$(printf '%s' "$hexs" | sed 's/../\\x&/g')"; } > "$r/$file"
  cur="$(wc -c < "$r/$file" | tr -d ' ')"
  [ "$size" -gt "$cur" ] && head -c $((size - cur)) /dev/zero >> "$r/$file"
  git -C "$r" add -A; out="$(cd "$r" && "$here/tracked-files.sh" 2>&1)"; rc=$?
  echo . >> "$tmp/n"
  if [ "$want" = ok ] && [ "$rc" != 0 ]; then echo . >> "$tmp/f"; echo "FAIL: $desc: failed: $out"; fi
  if [ "$want" = fail ] && [ "$rc" = 0 ]; then echo . >> "$tmp/f"; echo "FAIL: $desc: passed but must fail"; fi
  git -C "$r" rm -q -f --cached "$file" >/dev/null 2>&1; rm -f "$r/$file"
}
t ok   "empty repository content: a text file"         notes.txt 68656c6c6f0a
t ok   "a normal PNG"                                  docs/a.png 89504e470d0a1a0a0000000d49484452 4000
t ok   "a PNG at 400 KB (under the limit)"             docs/big.png 89504e470d0a1a0a 400000
t ok   "a Java class (cafebabe, version 52)"           x/A.class cafebabe00000034 200
t ok   "a three byte file"                             tiny 414243
t fail "a 64-bit Mach-O (arm64) header"                qv-keysets cffaedfe0c000001 4096
t fail "a 64-bit Mach-O under a harmless name"         docs/logo.png cffaedfe0c000001 4096
t fail "a 32-bit Mach-O header"                        a.out feedface00000007 100
t fail "a Mach-O in the other byte order"              b.out cefaedfe 100
t fail "a fat Mach-O (cafebabe, 2 architectures)"      fat cafebabe00000002 100
t fail "an ELF header"                                 bin/tool 7f454c4602010100 100
t fail "an ELF object named .txt"                      notes2.txt 7f454c46 20
t fail "an ar archive (static library)"                lib/libx.a 213c617263683e0a 100
# a PE file: MZ, e_lfanew = 0x40 at offset 0x3c, "PE\0\0" at 0x40
pe="4d5a$(printf '00%.0s' $(seq 1 58))4000000050450000"
t fail "a PE executable"                               win/tool.exe "$pe" 200
t ok   "MZ without a PE signature (not an executable)" odd/mz.txt 4d5a0000 200
t fail "a file over the size limit"                    data/big.bin 00 600000
t ok   "exactly the limit"                             data/limit.bin 00 524288
t fail "over the limit by one byte"                    data/limit1.bin 00 524289
printf 'data/big.bin\tdocumented large file\n' > "$QV_TRACKED_EXCEPTIONS"
t ok   "a large file with a reviewed exception"        data/big.bin 00 600000
t fail "an exception does not cover a Mach-O"          data/big.bin cffaedfe0c000001 600000
printf 'data/gone.bin\tnot tracked any more\n' > "$QV_TRACKED_EXCEPTIONS"
t fail "a stale exception"                             notes.txt 68656c6c6f0a
: > "$QV_TRACKED_EXCEPTIONS"
# the real tree
echo . >> "$tmp/n"; (cd "$here/.." && QV_TRACKED_EXCEPTIONS="$here/tracked-files-exceptions" "$here/tracked-files.sh" > "$tmp/real" 2>&1) || { echo . >> "$tmp/f"; echo "FAIL: this repository does not pass: $(cat "$tmp/real")"; }
total="$(wc -l < "$tmp/n" | tr -d ' ')"; fails="$(wc -l < "$tmp/f" | tr -d ' ')"
echo "tracked-files_test: $((total - fails))/$total checks passed"
[ "$fails" = 0 ]
