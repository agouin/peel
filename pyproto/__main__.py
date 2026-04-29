"""shrinkex CLI.

    shrinkex archive.tar.zst                  # auto: streams tar to ./
    shrinkex archive.tar.zst -C /opt/out      # tar streaming into /opt/out
    shrinkex blob.zst -o blob                 # raw single-file output
    shrinkex archive.tar.zst --unlink         # delete source on success
"""
from __future__ import annotations

import argparse
import os
import sys

from . import PunchingExtractor, ExtractionError, get_decoder_for_path
# Importing the decoder modules registers them. Add new formats here.
from .decoders import zstd_decoder, gzip_decoder  # noqa: F401
from .sinks import RawFileSink, TarStreamingSink


def _is_tar_archive(path: str) -> bool:
    """Heuristic: foo.tar.zst, foo.tar.gz, foo.tgz, foo.tzst -> tar."""
    name = path.lower()
    return (
        name.endswith(".tar.zst") or name.endswith(".tar.zstd")
        or name.endswith(".tar.gz") or name.endswith(".tar.gzip")
        or name.endswith(".tgz") or name.endswith(".tzst")
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shrinkex")
    p.add_argument("source", help="compressed archive to extract")
    p.add_argument("-C", "--directory", default=".",
                   help="output directory for tar archives (default: cwd)")
    p.add_argument("-o", "--output",
                   help="output file (for non-tar single-file streams)")
    p.add_argument("--unlink", action="store_true",
                   help="delete source file on successful extraction")
    p.add_argument("--safety-margin", type=int, default=64 * 1024,
                   help="bytes to keep unpunched behind decoder (default 64K)")
    p.add_argument("--punch-threshold", type=int, default=4 * 1024 * 1024,
                   help="min gap between punches (default 4M)")
    args = p.parse_args(argv)

    decoder = get_decoder_for_path(args.source)
    if decoder is None:
        print(f"shrinkex: no decoder registered for {args.source}",
              file=sys.stderr)
        return 2

    if _is_tar_archive(args.source):
        sink = TarStreamingSink(args.directory)
    else:
        out = args.output or _strip_known_suffix(args.source)
        if out == args.source:
            print("shrinkex: refusing to overwrite source; pass -o",
                  file=sys.stderr)
            return 2
        sink = RawFileSink(out)

    extractor = PunchingExtractor(
        safety_margin=args.safety_margin,
        punch_threshold=args.punch_threshold,
        unlink_on_success=args.unlink,
    )

    try:
        stats = extractor.extract(args.source, decoder, sink)
    except ExtractionError as e:
        print(f"shrinkex: {e}", file=sys.stderr)
        return 1

    print(
        f"in={stats.bytes_in:,}B out={stats.bytes_out:,}B "
        f"punched={stats.bytes_punched:,}B "
        f"({stats.punch_calls} calls)",
        file=sys.stderr,
    )
    return 0


def _strip_known_suffix(path: str) -> str:
    for suf in (".tar.zst", ".tar.zstd", ".tar.gz", ".tgz", ".tzst",
                ".zst", ".zstd", ".gz", ".gzip"):
        if path.lower().endswith(suf):
            return path[: -len(suf)]
    return path + ".out"


if __name__ == "__main__":
    sys.exit(main())
