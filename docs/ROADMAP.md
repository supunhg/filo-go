# Roadmap

filo aims to be the tool you reach for first when you need to know what a file is and what is
inside it. It should give answers precise enough to act on, fast enough to run on everything,
and easy to automate. Accuracy comes before new features.

This roadmap is a direction, not a promise. Open an issue to discuss priorities.

## v0.6: trust (in progress)

- [x] Validated signature engine (44 formats) behind `scan`, `extract` and `analyze`
- [x] Evidence-based encryption detection (containers and a chi-square test) instead of cipher guessing
- [x] Errors printed; colors only on terminals; deterministic output
- [x] REST API locked down by default; MCP server conforms to the specification
- [x] Safe extraction (no path traversal, decompression limits)
- [x] CI on Linux, macOS and Windows; reproducible releases with SBOMs and provenance
- [ ] Embed the YAML format database in the binary
- [ ] Move `carve` onto the signature engine and unify entropy wording
- [ ] Stream large files instead of loading them into memory

## Next

- **Recursive extraction:** unpack what `extract` finds (archives, compressed streams,
  filesystems) into a tree, like `binwalk -Me`.
- **Filesystem unpacking:** SquashFS, CramFS and JFFS2 contents, so `firmware -x` delivers on
  its name.
- **More formats:** ext2/3/4, FAT, NTFS boot sectors, ISO 9660, Android boot images, Intel HEX,
  UEFI capsules.
- **YARA:** integrate a complete YARA implementation instead of the current small subset.
- **Homebrew and Scoop** packages.

## Later

- Format analyzers (PE, ELF, OOXML, PCAP, EVTX) brought up to the accuracy bar of the core
  commands, with corpus-based tests.
- Performance regression tracking in CI.
- Decide the future of the experimental commands (`teach`, `lineage`, `profile`, `plugins`,
  `timeline`): finish them or remove them.
