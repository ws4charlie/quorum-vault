#!/usr/bin/env bash
# Fails when a tracked file is a compiled executable or object, or is larger than the limit. Runs in the always-running `changes` job of ci.yml.
# Background: a 29 MB built binary (qv-keysets, Mach-O) was committed with a feature PR and nobody noticed.
# - Executables and objects are found by their first bytes, never by name or extension: Mach-O (thin, 32/64-bit, either byte order; fat), ELF, PE/COFF
#   executables and DLLs (MZ header with a PE signature) and `ar` archives (static libraries). No exception is possible: build outputs do not belong in git.
# - Size: any tracked file above LIMIT bytes fails, unless its path is in ci/tracked-files-exceptions (`<path><TAB><reason>`, reviewed). The limit is about
#   five times the largest file in the tree when it was chosen (docs/images/evm.png, 107 KB).
# Usage: ci/tracked-files.sh   (in a git checkout; QV_TRACKED_EXCEPTIONS overrides the exceptions file, for the test)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
LIMIT=524288
exc="${QV_TRACKED_EXCEPTIONS:-$here/tracked-files-exceptions}"
cd "$(git rev-parse --show-toplevel)" || exit 2
bad=0

# one `git cat-file --batch` process reads every tracked blob; perl keeps its first 64 bytes and its size (a fork per file took 20 s)
list="$(mktemp)"; res="$(mktemp)"; trap 'rm -f "$list" "$res"' EXIT
git ls-files -s -z | while IFS= read -r -d '' rec; do
  meta="${rec%%$'\t'*}"; path="${rec#*$'\t'}"
  set -- $meta; mode="$1"; sha="$2"
  [ "$mode" = 160000 ] && continue      # a submodule has no blob here
  [ "$mode" = 120000 ] && continue      # a symlink's blob is its target text
  printf '%s %s %s\n' "$mode" "$sha" "$path"
done > "$list"
perl -MIPC::Open2 -e '
  my $pid = open2(my $out, my $in, "git", "cat-file", "--batch");
  open(my $l, "<", $ARGV[0]) or die;
  while (my $line = <$l>) {
    chomp $line; my ($mode, $sha, $path) = split(/ /, $line, 3);
    print $in "$sha\n"; $in->flush;
    my $hdr = <$out>; my (undef, undef, $size) = split(/ /, $hdr); chomp $size;
    my ($head, $left) = ("", $size);
    while ($left > 0) { my $n = read($out, my $buf, $left > 65536 ? 65536 : $left); die "short read" unless $n; $head .= $buf if length($head) < 64; $left -= $n; }
    read($out, my $nl, 1);
    $head = substr($head, 0, 64);
    my $h = unpack("H*", $head); my $kind = "";
    if ($size >= 4) {
      if ($h =~ /^(feedface|feedfacf|cefaedfe|cffaedfe)/) { $kind = "Mach-O executable or object" }
      elsif ($h =~ /^7f454c46/) { $kind = "ELF executable or object" }
      elsif ($h =~ /^213c617263683e0a/) { $kind = "ar archive (static library)" }
      elsif ($h =~ /^cafebabe/ && length($h) >= 16 && hex(substr($h, 8, 8)) < 45) { $kind = "fat Mach-O binary" }
      elsif ($h =~ /^4d5a/ && length($h) >= 128) {
        my $off = unpack("V", substr($head, 60, 4));
        if ($off > 0 && $off < 1048576 && $size >= $off + 4) {
          # the PE signature can lie beyond the 64 bytes kept: read it from the blob again
          my $sig = ""; if ($off + 4 <= 64) { $sig = substr($head, $off, 4) } else { $sig = `git cat-file blob $sha | tail -c +@{[$off + 1]} | head -c 4`; }
          $kind = "PE executable or DLL" if $sig eq "PE\0\0";
        }
      }
    }
    print(($kind eq "" ? "-" : $kind) . "\t$size\t$path\n");
  }' "$list" > "$res"

while IFS=$'\t' read -r kind size path; do
  if [ "$kind" != - ]; then bad=1; echo "BUILD OUTPUT: $path is a $kind ($size bytes). Remove it from git (and ignore it in .gitignore); a build output is never committed."; continue; fi
  if [ "$size" -gt "$LIMIT" ]; then
    if [ -r "$exc" ] && awk -F'\t' -v p="$path" '$0 !~ /^#/ && $1==p && $2!="" {f=1} END{exit !f}' "$exc"; then continue; fi
    bad=1; echo "TOO LARGE: $path is $size bytes (limit $LIMIT). Do not commit it; if it must live in git, add '<path><TAB><reason>' to ci/tracked-files-exceptions (reviewed)."
  fi
done < "$res"

# an exception for a file that is gone or is not large any more is removed
if [ -r "$exc" ]; then
  while IFS=$'\t' read -r p r || [ -n "$p" ]; do
    case "$p" in ''|'#'*) continue ;; esac
    if ! awk -F'\t' -v p="$p" '$3==p {f=1} END{exit !f}' "$res"; then bad=1; echo "STALE exception: $p is not tracked"; fi
  done < "$exc"
fi
[ "$bad" = 0 ] && echo "tracked-files: ok (no build output, nothing over $LIMIT bytes)"
exit "$bad"
