package signature

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

// sigs is the signature table. Order matters only among signatures that share
// the same magic bytes: the first one whose validator succeeds wins.
var sigs = []sig{
	// Images
	{format: "png", mime: "image/png", magic: []byte("\x89PNG\r\n\x1a\n"), check: checkPNG},
	{format: "jpeg", mime: "image/jpeg", magic: []byte{0xFF, 0xD8, 0xFF}, check: checkJPEG},
	{format: "gif", mime: "image/gif", magic: []byte("GIF8"), check: checkGIF},
	{format: "bmp", mime: "image/bmp", magic: []byte("BM"), check: checkBMP},
	{format: "tiff", mime: "image/tiff", magic: []byte("II*\x00"), check: checkTIFF},
	{format: "tiff", mime: "image/tiff", magic: []byte("MM\x00*"), check: checkTIFF},
	{format: "ico", mime: "image/vnd.microsoft.icon", magic: []byte{0, 0, 1, 0}, check: checkICO},
	{format: "webp", mime: "image/webp", magic: []byte("RIFF"), check: checkRIFF("WEBP", "WebP image")},

	// Audio and video
	{format: "wav", mime: "audio/wav", magic: []byte("RIFF"), check: checkRIFF("WAVE", "WAVE audio")},
	{format: "avi", mime: "video/x-msvideo", magic: []byte("RIFF"), check: checkRIFF("AVI ", "AVI video")},
	{format: "flac", mime: "audio/flac", magic: []byte("fLaC"), check: checkFLAC},
	{format: "ogg", mime: "audio/ogg", magic: []byte("OggS"), check: checkOgg},
	{format: "mp3", mime: "audio/mpeg", magic: []byte("ID3"), check: checkID3},
	{format: "mkv", mime: "video/x-matroska", magic: []byte{0x1A, 0x45, 0xDF, 0xA3}, check: checkEBML},
	{format: "mp4", mime: "video/mp4", magic: []byte("ftyp"), at: 4, check: checkISOBMFF},

	// Documents
	{format: "pdf", mime: "application/pdf", magic: []byte("%PDF-"), check: checkPDF},
	{format: "ole2", mime: "application/x-ole-storage", magic: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, check: checkOLE2},
	{format: "rtf", mime: "application/rtf", magic: []byte(`{\rtf1`), check: checkFixed("Rich Text Format document")},
	{format: "pem", mime: "application/x-pem-file", magic: []byte("-----BEGIN "), check: checkPEM},

	// Archives and compression
	{format: "zip", mime: "application/zip", magic: []byte("PK\x03\x04"), check: checkZIP},
	{format: "gzip", mime: "application/gzip", magic: []byte{0x1F, 0x8B, 0x08}, check: checkGzip},
	{format: "bzip2", mime: "application/x-bzip2", magic: []byte("BZh"), check: checkBzip2},
	{format: "xz", mime: "application/x-xz", magic: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, check: checkXZ},
	{format: "zstd", mime: "application/zstd", magic: []byte{0x28, 0xB5, 0x2F, 0xFD}, check: checkZstd},
	{format: "lz4", mime: "application/x-lz4", magic: []byte{0x04, 0x22, 0x4D, 0x18}, check: checkLZ4},
	{format: "lzma", mime: "application/x-lzma", magic: []byte{0x5D, 0x00, 0x00}, check: checkLZMA},
	{format: "7z", mime: "application/x-7z-compressed", magic: []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, check: check7z},
	{format: "rar", mime: "application/vnd.rar", magic: []byte("Rar!\x1a\x07"), check: checkRAR},
	{format: "tar", mime: "application/x-tar", magic: []byte("ustar"), at: 257, check: checkTar},
	{format: "cpio", mime: "application/x-cpio", magic: []byte("070701"), check: checkCPIO("new ASCII")},
	{format: "cpio", mime: "application/x-cpio", magic: []byte("070702"), check: checkCPIO("new ASCII with CRC")},
	{format: "cab", mime: "application/vnd.ms-cab-compressed", magic: []byte("MSCF\x00\x00\x00\x00"), check: checkCAB},

	// Executables and bytecode
	{format: "elf", mime: "application/x-elf", magic: []byte("\x7fELF"), check: checkELF},
	{format: "pe", mime: "application/vnd.microsoft.portable-executable", magic: []byte("MZ"), check: checkPE},
	{format: "macho", mime: "application/x-mach-binary", magic: []byte{0xFE, 0xED, 0xFA, 0xCE}, check: checkMachO},
	{format: "macho", mime: "application/x-mach-binary", magic: []byte{0xFE, 0xED, 0xFA, 0xCF}, check: checkMachO},
	{format: "macho", mime: "application/x-mach-binary", magic: []byte{0xCE, 0xFA, 0xED, 0xFE}, check: checkMachO},
	{format: "macho", mime: "application/x-mach-binary", magic: []byte{0xCF, 0xFA, 0xED, 0xFE}, check: checkMachO},
	{format: "macho", mime: "application/x-mach-binary", magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}, check: checkFatMachO},
	{format: "java-class", mime: "application/java-vm", magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}, check: checkJavaClass},
	{format: "dex", mime: "application/vnd.android.dex", magic: []byte("dex\n0"), check: checkDEX},
	{format: "wasm", mime: "application/wasm", magic: []byte("\x00asm\x01\x00\x00\x00"), check: checkFixed("WebAssembly module, version 1")},

	// Databases
	{format: "sqlite", mime: "application/vnd.sqlite3", magic: []byte("SQLite format 3\x00"), check: checkSQLite},

	// Firmware and filesystems
	{format: "squashfs", mime: "application/x-squashfs", magic: []byte("hsqs"), check: checkSquashFS(le)},
	{format: "squashfs", mime: "application/x-squashfs", magic: []byte("sqsh"), check: checkSquashFS(be)},
	{format: "cramfs", mime: "application/x-cramfs", magic: []byte{0x45, 0x3D, 0xCD, 0x28}, check: checkCramFS(le)},
	{format: "cramfs", mime: "application/x-cramfs", magic: []byte{0x28, 0xCD, 0x3D, 0x45}, check: checkCramFS(be)},
	{format: "uimage", mime: "application/x-uboot-image", magic: []byte{0x27, 0x05, 0x19, 0x56}, check: checkUImage},
	{format: "ubi", mime: "application/x-ubi", magic: []byte("UBI#"), check: checkUBI},
	{format: "ubifs", mime: "application/x-ubifs", magic: []byte{0x31, 0x18, 0x10, 0x06}, check: checkUBIFS},
	{format: "jffs2", mime: "application/x-jffs2", magic: []byte{0x85, 0x19}, check: checkJFFS2(le)},
	{format: "jffs2", mime: "application/x-jffs2", magic: []byte{0x19, 0x85}, check: checkJFFS2(be)},
	{format: "dtb", mime: "application/x-dtb", magic: []byte{0xD0, 0x0D, 0xFE, 0xED}, check: checkDTB},
}

func checkFixed(desc string) checkFunc {
	return func(d []byte) (string, int64, bool) { return desc, 0, true }
}

// ---------------------------------------------------------------- images

func checkPNG(d []byte) (string, int64, bool) {
	if len(d) < 26 || string(d[12:16]) != "IHDR" || be.Uint32(d[8:12]) != 13 {
		return "", 0, false
	}
	w, h := be.Uint32(d[16:20]), be.Uint32(d[20:24])
	depth, ctype := d[24], d[25]
	if w == 0 || h == 0 || w > 1<<24 || h > 1<<24 || !validPNGDepth(depth, ctype) {
		return "", 0, false
	}
	desc := fmt.Sprintf("PNG image, %d x %d, %d-bit %s", w, h, depth, pngColor(ctype))
	if len(d) >= 33 && crc32.ChecksumIEEE(d[12:29]) != be.Uint32(d[29:33]) {
		desc += ", bad IHDR CRC"
	}
	var size int64
	off := 8
	for off+12 <= len(d) {
		n := int(be.Uint32(d[off : off+4]))
		if n < 0 || n > len(d) {
			break
		}
		typ := string(d[off+4 : off+8])
		next := off + 12 + n
		if next > len(d) {
			break
		}
		if typ == "IEND" {
			size = int64(next)
			break
		}
		off = next
	}
	if size == 0 {
		desc += ", truncated"
	}
	return desc, size, true
}

func validPNGDepth(depth, ctype byte) bool {
	switch ctype {
	case 0:
		return depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16
	case 3:
		return depth == 1 || depth == 2 || depth == 4 || depth == 8
	case 2, 4, 6:
		return depth == 8 || depth == 16
	}
	return false
}

func pngColor(c byte) string {
	switch c {
	case 0:
		return "grayscale"
	case 2:
		return "RGB"
	case 3:
		return "palette"
	case 4:
		return "grayscale+alpha"
	case 6:
		return "RGBA"
	}
	return "unknown color"
}

func checkJPEG(d []byte) (string, int64, bool) {
	if len(d) < 4 {
		return "", 0, false
	}
	m := d[3]
	if !isJPEGFirstMarker(m) {
		return "", 0, false
	}
	desc := "JPEG image"
	switch {
	case len(d) >= 11 && m == 0xE0 && string(d[6:11]) == "JFIF\x00":
		desc += ", JFIF"
	case len(d) >= 11 && m == 0xE1 && string(d[6:10]) == "Exif":
		desc += ", EXIF"
	}
	off := 2
	var w, h uint16
	for off+2 <= len(d) {
		if d[off] != 0xFF {
			if off > 20 {
				return jpegDesc(desc, w, h) + ", corrupt", 0, true
			}
			return "", 0, false
		}
		marker := d[off+1]
		switch {
		case marker == 0xFF:
			off++
			continue
		case marker == 0xD9:
			return jpegDesc(desc, w, h), int64(off + 2), true
		case marker == 0x01 || isRST(marker):
			off += 2
			continue
		}
		if off+4 > len(d) {
			break
		}
		segLen := int(be.Uint16(d[off+2 : off+4]))
		if segLen < 2 || off+2+segLen > len(d) {
			break
		}
		if (marker >= 0xC0 && marker <= 0xCF) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC && segLen >= 7 {
			h, w = be.Uint16(d[off+5:off+7]), be.Uint16(d[off+7:off+9])
		}
		off += 2 + segLen
		if marker == 0xDA {
			// Skip entropy-coded data up to the next real marker.
			for off+1 < len(d) {
				if d[off] == 0xFF {
					nb := d[off+1]
					if nb != 0x00 && !isRST(nb) && nb != 0xFF {
						break
					}
				}
				off++
			}
		}
	}
	if off <= 4 {
		return "", 0, false
	}
	return jpegDesc(desc, w, h) + ", truncated", 0, true
}

// isJPEGFirstMarker reports whether m can follow the SOI marker: an APPn
// segment or one of the table/frame markers some encoders emit first.
func isJPEGFirstMarker(m byte) bool {
	switch {
	case m >= 0xE0 && m <= 0xEF:
		return true
	case m == 0xDB, m == 0xC0, m == 0xC2, m == 0xC4, m == 0xFE, m == 0xDD:
		return true
	}
	return false
}

// isRST reports whether m is a JPEG restart marker.
func isRST(m byte) bool { return m >= 0xD0 && m <= 0xD7 }

func jpegDesc(desc string, w, h uint16) string {
	if w > 0 && h > 0 {
		desc += fmt.Sprintf(", %d x %d", w, h)
	}
	return desc
}

func checkGIF(d []byte) (string, int64, bool) {
	if len(d) < 13 || (string(d[:6]) != "GIF87a" && string(d[:6]) != "GIF89a") {
		return "", 0, false
	}
	w, h := le.Uint16(d[6:8]), le.Uint16(d[8:10])
	if w == 0 || h == 0 {
		return "", 0, false
	}
	desc := fmt.Sprintf("GIF image, version %s, %d x %d", d[3:6], w, h)
	off := 13
	if d[10]&0x80 != 0 {
		off += 3 << (int(d[10]&7) + 1)
	}
	skipSub := func(o int) int {
		for o < len(d) {
			n := int(d[o])
			o++
			if n == 0 {
				return o
			}
			o += n
		}
		return -1
	}
	for off >= 0 && off < len(d) {
		switch d[off] {
		case 0x3B:
			return desc, int64(off + 1), true
		case 0x21:
			if off+2 > len(d) {
				off = -1
				continue
			}
			off = skipSub(off + 2)
		case 0x2C:
			if off+10 > len(d) {
				off = -1
				continue
			}
			flags := d[off+9]
			off += 10
			if flags&0x80 != 0 {
				off += 3 << (int(flags&7) + 1)
			}
			off = skipSub(off + 1)
		default:
			off = -1
		}
	}
	return desc + ", truncated", 0, true
}

func checkBMP(d []byte) (string, int64, bool) {
	if len(d) < 30 {
		return "", 0, false
	}
	size := int64(le.Uint32(d[2:6]))
	dataOff := le.Uint32(d[10:14])
	hdr := le.Uint32(d[14:18])
	if le.Uint32(d[6:10]) != 0 || size < 26 || int64(dataOff) >= size || dataOff < 14+hdr {
		return "", 0, false
	}
	switch hdr {
	case 12, 40, 52, 56, 64, 108, 124:
	default:
		return "", 0, false
	}
	var w, h int32
	var bpp uint16
	if hdr == 12 {
		w, h, bpp = int32(le.Uint16(d[18:20])), int32(le.Uint16(d[20:22])), le.Uint16(d[24:26])
	} else {
		w, h, bpp = int32(le.Uint32(d[18:22])), int32(le.Uint32(d[22:26])), le.Uint16(d[28:30])
	}
	if h < 0 {
		h = -h
	}
	if w <= 0 || h == 0 || w > 1<<16 || h > 1<<16 {
		return "", 0, false
	}
	switch bpp {
	case 1, 4, 8, 16, 24, 32:
	default:
		return "", 0, false
	}
	return fmt.Sprintf("BMP image, %d x %d, %d bpp", w, h, bpp), size, true
}

func checkTIFF(d []byte) (string, int64, bool) {
	if len(d) < 8 {
		return "", 0, false
	}
	order, name := binary.ByteOrder(le), "little-endian"
	if d[0] == 'M' {
		order, name = be, "big-endian"
	}
	ifd := order.Uint32(d[4:8])
	if ifd < 8 || int64(ifd)+2 > int64(len(d)) {
		return "", 0, false
	}
	n := order.Uint16(d[ifd : ifd+2])
	if n == 0 || n > 512 {
		return "", 0, false
	}
	return "TIFF image, " + name, 0, true
}

func checkICO(d []byte) (string, int64, bool) {
	if len(d) < 22 {
		return "", 0, false
	}
	count := int(le.Uint16(d[4:6]))
	if count == 0 || count > 64 || 6+16*count > len(d) {
		return "", 0, false
	}
	var end int64
	for i := 0; i < count; i++ {
		e := d[6+16*i:]
		planes, bpp := le.Uint16(e[4:6]), le.Uint16(e[6:8])
		sz, off := int64(le.Uint32(e[8:12])), int64(le.Uint32(e[12:16]))
		if e[3] != 0 || planes > 1 || sz == 0 || off < int64(6+16*count) {
			return "", 0, false
		}
		switch bpp {
		case 0, 1, 4, 8, 16, 24, 32:
		default:
			return "", 0, false
		}
		if off+sz > end {
			end = off + sz
		}
	}
	if end > int64(len(d)) {
		return "", 0, false
	}
	return fmt.Sprintf("Windows icon, %d image(s)", count), end, true
}

func checkRIFF(form, desc string) checkFunc {
	return func(d []byte) (string, int64, bool) {
		if len(d) < 12 || string(d[8:12]) != form {
			return "", 0, false
		}
		size := int64(le.Uint32(d[4:8])) + 8
		if size < 12 {
			return "", 0, false
		}
		return desc, size, true
	}
}

// ------------------------------------------------------- audio and video

func checkFLAC(d []byte) (string, int64, bool) {
	if len(d) < 42 || d[4]&0x7F != 0 || int(d[5])<<16|int(d[6])<<8|int(d[7]) != 34 {
		return "", 0, false
	}
	rate := int(d[18])<<12 | int(d[19])<<4 | int(d[20])>>4
	ch := int(d[20]>>1&7) + 1
	if rate == 0 {
		return "", 0, false
	}
	return fmt.Sprintf("FLAC audio, %d Hz, %d channel(s)", rate, ch), 0, true
}

func checkOgg(d []byte) (string, int64, bool) {
	if len(d) < 27 || d[4] != 0 || d[5]&^0x07 != 0 || d[5]&0x02 == 0 {
		return "", 0, false
	}
	return "Ogg container", 0, true
}

func checkID3(d []byte) (string, int64, bool) {
	if len(d) < 10 || d[3] < 2 || d[3] > 4 || d[4] == 0xFF || d[5]&0x0F != 0 {
		return "", 0, false
	}
	for _, b := range d[6:10] {
		if b&0x80 != 0 {
			return "", 0, false
		}
	}
	return fmt.Sprintf("MP3 audio, ID3v2.%d tag", d[3]), 0, true
}

func checkEBML(d []byte) (string, int64, bool) {
	head := d[:min(len(d), 64)]
	switch {
	case bytes.Contains(head, []byte("webm")):
		return "WebM video", 0, true
	case bytes.Contains(head, []byte("matroska")):
		return "Matroska video", 0, true
	}
	return "", 0, false
}

func checkISOBMFF(d []byte) (string, int64, bool) {
	if len(d) < 16 {
		return "", 0, false
	}
	n := be.Uint32(d[0:4])
	if n < 16 || n > 512 || n%4 != 0 {
		return "", 0, false
	}
	brand := d[8:12]
	for _, b := range brand {
		if b < 0x20 || b > 0x7E {
			return "", 0, false
		}
	}
	// Walk top-level boxes to find where the file ends.
	var off int64
	for off+8 <= int64(len(d)) {
		sz := int64(be.Uint32(d[off : off+4]))
		typ := d[off+4 : off+8]
		for _, b := range typ {
			if b < 0x20 || b > 0x7E {
				goto done
			}
		}
		if sz == 1 && off+16 <= int64(len(d)) {
			sz = int64(be.Uint64(d[off+8 : off+16]))
		}
		if sz < 8 || off+sz > int64(len(d)) {
			break
		}
		off += sz
	}
done:
	desc := fmt.Sprintf("ISO media, brand %q", string(bytes.TrimRight(brand, " ")))
	switch string(brand) {
	case "heic", "heix", "mif1":
		desc = "HEIF image" + desc[9:]
	case "M4A ":
		desc = "MPEG-4 audio" + desc[9:]
	case "qt  ":
		desc = "QuickTime movie" + desc[9:]
	}
	if off <= int64(n) {
		off = 0
	}
	return desc, off, true
}

// ------------------------------------------------------------- documents

func checkPDF(d []byte) (string, int64, bool) {
	if len(d) < 8 || d[5] < '1' || d[5] > '2' || d[6] != '.' || d[7] < '0' || d[7] > '9' {
		return "", 0, false
	}
	desc := "PDF document, version " + string(d[5:8])
	// The last %%EOF before the next PDF header (or end of data) ends the
	// file; incremental updates append further %%EOF markers.
	limit := len(d)
	if next := bytes.Index(d[8:], []byte("%PDF-")); next >= 0 {
		limit = next + 8
	}
	eof := bytes.LastIndex(d[:limit], []byte("%%EOF"))
	if eof < 0 {
		return desc + ", missing %%EOF", 0, true
	}
	end := eof + 5
	for end < limit && (d[end] == '\r' || d[end] == '\n') {
		end++
	}
	return desc, int64(end), true
}

func checkOLE2(d []byte) (string, int64, bool) {
	if len(d) < 512 || le.Uint16(d[28:30]) != 0xFFFE {
		return "", 0, false
	}
	shift := le.Uint16(d[30:32])
	if shift != 9 && shift != 12 {
		return "", 0, false
	}
	return "OLE2 compound document (MS Office 97-2003, MSI, ...)", 0, true
}

// isPEMLabelChar reports whether c may appear in a PEM label such as
// "RSA PRIVATE KEY" or "PKCS7".
func isPEMLabelChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '#'
}

func checkPEM(d []byte) (string, int64, bool) {
	line := d[:min(len(d), 80)]
	end := bytes.Index(line[11:], []byte("-----"))
	if end <= 0 {
		return "", 0, false
	}
	label := string(line[11 : 11+end])
	for _, c := range label {
		if !isPEMLabelChar(c) {
			return "", 0, false
		}
	}
	footer := []byte("-----END " + label + "-----")
	var size int64
	if i := bytes.Index(d, footer); i > 0 {
		size = int64(i + len(footer))
	}
	return "PEM " + label, size, true
}

// --------------------------------------------------- archives/compression

var zipMethods = map[uint16]string{0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 98: "ppmd", 99: "AES-encrypted"}

func checkZIP(d []byte) (string, int64, bool) {
	if len(d) < 30 {
		return "", 0, false
	}
	ver, flags, method := le.Uint16(d[4:6]), le.Uint16(d[6:8]), le.Uint16(d[8:10])
	nameLen := int(le.Uint16(d[26:28]))
	mname, known := zipMethods[method]
	if ver > 63 || !known || nameLen == 0 || nameLen > 1024 || 30+nameLen > len(d) {
		return "", 0, false
	}
	name := d[30 : 30+nameLen]
	desc := fmt.Sprintf("ZIP archive, first entry %q (%s)", string(name), mname)
	if flags&1 != 0 {
		desc += ", encrypted"
	}
	// Find the End Of Central Directory record that belongs to this archive.
	for off := 30 + nameLen; ; {
		i := bytes.Index(d[off:], []byte("PK\x05\x06"))
		if i < 0 {
			break
		}
		e := off + i
		if e+22 <= len(d) {
			commentLen := int(le.Uint16(d[e+20 : e+22]))
			cdSize, cdOff := int(le.Uint32(d[e+12:e+16])), int(le.Uint32(d[e+16:e+20]))
			if cdOff+cdSize == e || cdOff == 0xFFFFFFFF {
				entries := le.Uint16(d[e+10 : e+12])
				return fmt.Sprintf("%s, %d entr%s", desc, entries, plural(int(entries), "y", "ies")), int64(e + 22 + commentLen), true
			}
		}
		off = e + 4
	}
	return desc + ", no central directory", 0, true
}

func checkGzip(d []byte) (string, int64, bool) {
	if len(d) < 18 || d[3]&0xE0 != 0 || (d[9] > 13 && d[9] != 255) {
		return "", 0, false
	}
	if xfl := d[8]; xfl != 0 && xfl != 2 && xfl != 4 {
		return "", 0, false
	}
	desc := "gzip compressed data"
	if d[3]&0x08 != 0 {
		off := 10
		if d[3]&0x04 != 0 {
			if len(d) < 12 {
				return "", 0, false
			}
			off += 2 + int(le.Uint16(d[10:12]))
		}
		if off < len(d) {
			if end := bytes.IndexByte(d[off:min(len(d), off+256)], 0); end > 0 {
				desc += fmt.Sprintf(", original name %q", string(d[off:off+end]))
			}
		}
	}
	return desc, 0, true
}

func checkBzip2(d []byte) (string, int64, bool) {
	if len(d) < 10 || d[3] < '1' || d[3] > '9' || string(d[4:10]) != "\x31\x41\x59\x26\x53\x59" {
		return "", 0, false
	}
	return fmt.Sprintf("bzip2 compressed data, block size %dk", int(d[3]-'0')*100), 0, true
}

func checkXZ(d []byte) (string, int64, bool) {
	if len(d) < 12 || d[6] != 0 || d[7]&0xF0 != 0 || crc32.ChecksumIEEE(d[6:8]) != le.Uint32(d[8:12]) {
		return "", 0, false
	}
	return "XZ compressed data", 0, true
}

func checkZstd(d []byte) (string, int64, bool) {
	if len(d) < 6 || d[4]&0x08 != 0 {
		return "", 0, false
	}
	return "Zstandard compressed data", 0, true
}

func checkLZ4(d []byte) (string, int64, bool) {
	if len(d) < 7 || d[4]>>6 != 1 || d[4]&0x02 != 0 || d[5]&0x8F != 0 || d[5]>>4 < 4 {
		return "", 0, false
	}
	return "LZ4 compressed data", 0, true
}

func checkLZMA(d []byte) (string, int64, bool) {
	if len(d) < 13 {
		return "", 0, false
	}
	dict := le.Uint32(d[1:5])
	if dict < 1<<12 || dict&(dict-1) != 0 {
		return "", 0, false
	}
	usize := le.Uint64(d[5:13])
	if usize != ^uint64(0) && (usize == 0 || usize > 1<<36) {
		return "", 0, false
	}
	desc := fmt.Sprintf("LZMA compressed data, dictionary %d KiB", dict>>10)
	if usize != ^uint64(0) {
		desc += fmt.Sprintf(", uncompressed size %d", usize)
	}
	return desc, 0, true
}

func check7z(d []byte) (string, int64, bool) {
	if len(d) < 32 || d[6] != 0 {
		return "", 0, false
	}
	if crc32.ChecksumIEEE(d[12:32]) != le.Uint32(d[8:12]) {
		return "", 0, false
	}
	size := int64(32) + int64(le.Uint64(d[12:20])) + int64(le.Uint64(d[20:28]))
	return fmt.Sprintf("7-zip archive, version 0.%d", d[7]), size, true
}

func checkRAR(d []byte) (string, int64, bool) {
	if len(d) < 8 {
		return "", 0, false
	}
	switch {
	case d[6] == 0x00:
		return "RAR archive, version 4", 0, true
	case d[6] == 0x01 && d[7] == 0x00:
		return "RAR archive, version 5", 0, true
	}
	return "", 0, false
}

func checkTar(d []byte) (string, int64, bool) {
	if len(d) < 512 || (string(d[257:263]) != "ustar\x00" && string(d[257:265]) != "ustar  \x00") {
		return "", 0, false
	}
	// Verify the header checksum: the sum of all bytes with the checksum
	// field read as spaces.
	var sum int64
	for i, b := range d[:512] {
		if i >= 148 && i < 156 {
			b = ' '
		}
		sum += int64(b)
	}
	want, ok := parseOctal(d[148:156])
	if !ok || want != sum {
		return "", 0, false
	}
	name := string(bytes.TrimRight(d[:100], "\x00"))
	return fmt.Sprintf("POSIX tar archive, first entry %q", name), 0, true
}

func checkCPIO(kind string) checkFunc {
	return func(d []byte) (string, int64, bool) {
		if len(d) < 110 {
			return "", 0, false
		}
		for _, c := range d[6:110] {
			if !isHexDigit(c) {
				return "", 0, false
			}
		}
		return "cpio archive, " + kind, 0, true
	}
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func checkCAB(d []byte) (string, int64, bool) {
	if len(d) < 36 || d[24] != 3 || d[25] != 1 {
		return "", 0, false
	}
	size := int64(le.Uint32(d[8:12]))
	if size < 36 {
		return "", 0, false
	}
	return fmt.Sprintf("Microsoft Cabinet archive, %d file(s)", le.Uint16(d[28:30])), size, true
}

// --------------------------------------------------------- executables

var elfMachines = map[uint16]string{
	0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390",
	0x28: "ARM", 0x2A: "SuperH", 0x2B: "SPARC V9", 0x32: "IA-64", 0x3E: "x86-64", 0xB7: "AArch64",
	0xF3: "RISC-V", 0xF7: "eBPF", 0x102: "LoongArch",
}

var elfTypes = map[uint16]string{1: "relocatable", 2: "executable", 3: "shared object", 4: "core file"}

func checkELF(d []byte) (string, int64, bool) {
	if len(d) < 52 || (d[4] != 1 && d[4] != 2) || (d[5] != 1 && d[5] != 2) || d[6] != 1 {
		return "", 0, false
	}
	order := binary.ByteOrder(le)
	if d[5] == 2 {
		order = be
	}
	typ := order.Uint16(d[16:18])
	typName, ok := elfTypes[typ]
	if !ok {
		return "", 0, false
	}
	machine := order.Uint16(d[18:20])
	mname, ok := elfMachines[machine]
	if !ok {
		mname = fmt.Sprintf("machine 0x%x", machine)
	}
	bits := 32
	var shoff, phoff int64
	var shentsize, shnum, phentsize, phnum int64
	if d[4] == 2 {
		if len(d) < 64 {
			return "", 0, false
		}
		bits = 64
		phoff, shoff = int64(order.Uint64(d[32:40])), int64(order.Uint64(d[40:48]))
		phentsize, phnum = int64(order.Uint16(d[54:56])), int64(order.Uint16(d[56:58]))
		shentsize, shnum = int64(order.Uint16(d[58:60])), int64(order.Uint16(d[60:62]))
	} else {
		phoff, shoff = int64(order.Uint32(d[28:32])), int64(order.Uint32(d[32:36]))
		phentsize, phnum = int64(order.Uint16(d[42:44])), int64(order.Uint16(d[44:46]))
		shentsize, shnum = int64(order.Uint16(d[46:48])), int64(order.Uint16(d[48:50]))
	}
	end := shoff + shentsize*shnum
	// Segments can extend past the section header table.
	if phoff > 0 && phentsize >= 32 && phoff+phentsize*phnum <= int64(len(d)) {
		for i := int64(0); i < phnum; i++ {
			p := d[phoff+i*phentsize:]
			var off, filesz int64
			if bits == 64 {
				off, filesz = int64(order.Uint64(p[8:16])), int64(order.Uint64(p[32:40]))
			} else {
				off, filesz = int64(order.Uint32(p[4:8])), int64(order.Uint32(p[16:20]))
			}
			if off+filesz > end {
				end = off + filesz
			}
		}
	}
	endian := "LSB"
	if d[5] == 2 {
		endian = "MSB"
	}
	if end < 0 {
		end = 0
	}
	return fmt.Sprintf("ELF %d-bit %s %s, %s", bits, endian, typName, mname), end, true
}

var peMachines = map[uint16]string{0x14C: "Intel 386", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0xAA64: "ARM64", 0x200: "IA-64", 0xEBC: "EFI byte code"}

func checkPE(d []byte) (string, int64, bool) {
	if len(d) < 64 {
		return "", 0, false
	}
	lfanew := int64(le.Uint32(d[60:64]))
	if lfanew < 64 || lfanew > 1<<16 || lfanew+24 > int64(len(d)) || string(d[lfanew:lfanew+4]) != "PE\x00\x00" {
		return "", 0, false
	}
	coff := d[lfanew+4:]
	machine := le.Uint16(coff[0:2])
	nsec := int64(le.Uint16(coff[2:4]))
	optSize := int64(le.Uint16(coff[16:18]))
	chars := le.Uint16(coff[18:20])
	mname, ok := peMachines[machine]
	if !ok {
		mname = fmt.Sprintf("machine 0x%x", machine)
	}
	kind := "executable"
	if chars&0x2000 != 0 {
		kind = "DLL"
	}
	bits := ""
	optOff := lfanew + 24
	sub := ""
	if optOff+2 <= int64(len(d)) {
		switch le.Uint16(d[optOff : optOff+2]) {
		case 0x10B:
			bits = "PE32"
		case 0x20B:
			bits = "PE32+"
		}
		if optOff+70 <= int64(len(d)) {
			switch le.Uint16(d[optOff+68 : optOff+70]) {
			case 1:
				sub = "native"
			case 2:
				sub = "GUI"
			case 3:
				sub = "console"
			case 10, 11, 12:
				sub = "EFI"
			}
		}
	}
	if bits == "" {
		bits = "PE"
	}
	desc := fmt.Sprintf("%s %s, %s", bits, kind, mname)
	if sub != "" {
		desc += ", " + sub
	}
	// File size is the end of the furthest raw section; anything after it is
	// an overlay (installers, appended payloads).
	secOff := optOff + optSize
	var end int64
	if nsec > 0 && nsec <= 96 && secOff+nsec*40 <= int64(len(d)) {
		end = secOff + nsec*40
		for i := int64(0); i < nsec; i++ {
			s := d[secOff+i*40:]
			raw, rawOff := int64(le.Uint32(s[16:20])), int64(le.Uint32(s[20:24]))
			if rawOff+raw > end {
				end = rawOff + raw
			}
		}
		// The certificate table lives after the sections.
		ddOff := optOff + 128
		if bits == "PE32+" {
			ddOff = optOff + 144
		}
		if ddOff+8 <= int64(len(d)) && ddOff+8 <= secOff {
			certOff, certSize := int64(le.Uint32(d[ddOff:ddOff+4])), int64(le.Uint32(d[ddOff+4:ddOff+8]))
			if certOff > 0 && certOff+certSize > end {
				end = certOff + certSize
			}
		}
	}
	return desc, end, true
}

var machoCPUs = map[uint32]string{7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 0x0200000C: "ARM64_32", 18: "PowerPC", 0x01000012: "PowerPC64"}

var machoTypes = map[uint32]string{1: "object", 2: "executable", 6: "dylib", 7: "dynamic linker", 8: "bundle", 10: "dSYM", 11: "kext"}

func checkMachO(d []byte) (string, int64, bool) {
	if len(d) < 28 {
		return "", 0, false
	}
	order := binary.ByteOrder(be)
	if d[0] == 0xCE || d[0] == 0xCF {
		order = le
	}
	is64 := d[3] == 0xCF || d[0] == 0xCF
	cpu := order.Uint32(d[4:8])
	ftype := order.Uint32(d[12:16])
	cname, ok := machoCPUs[cpu]
	if !ok {
		return "", 0, false
	}
	tname, ok := machoTypes[ftype]
	if !ok {
		return "", 0, false
	}
	bits := 32
	if is64 {
		bits = 64
	}
	return fmt.Sprintf("Mach-O %d-bit %s, %s", bits, tname, cname), 0, true
}

func checkFatMachO(d []byte) (string, int64, bool) {
	if len(d) < 8 {
		return "", 0, false
	}
	n := be.Uint32(d[4:8])
	// Java class files share this magic; their next field is the minor
	// version followed by a major version >= 45, which reads as a large count.
	if n == 0 || n > 20 || 8+int(n)*20 > len(d) {
		return "", 0, false
	}
	var end int64
	var arches []string
	for i := 0; i < int(n); i++ {
		a := d[8+i*20:]
		cpu := be.Uint32(a[0:4])
		off, size := int64(be.Uint32(a[8:12])), int64(be.Uint32(a[12:16]))
		name, ok := machoCPUs[cpu]
		if !ok {
			return "", 0, false
		}
		arches = append(arches, name)
		if off+size > end {
			end = off + size
		}
	}
	return fmt.Sprintf("Mach-O universal binary (%s)", joinComma(arches)), end, true
}

func checkJavaClass(d []byte) (string, int64, bool) {
	if len(d) < 10 {
		return "", 0, false
	}
	major := be.Uint16(d[6:8])
	if major < 45 || major > 80 {
		return "", 0, false
	}
	return fmt.Sprintf("Java class file, version %d.%d (Java %d)", major, be.Uint16(d[4:6]), int(major)-44), 0, true
}

func checkDEX(d []byte) (string, int64, bool) {
	if len(d) < 112 || d[7] != 0 || d[4] < '0' || d[4] > '9' {
		return "", 0, false
	}
	size := int64(le.Uint32(d[32:36]))
	if size < 112 || le.Uint32(d[36:40]) != 0x70 {
		return "", 0, false
	}
	return "Android DEX bytecode, version " + string(d[4:7]), size, true
}

// ------------------------------------------------------------- databases

func checkSQLite(d []byte) (string, int64, bool) {
	if len(d) < 100 {
		return "", 0, false
	}
	ps := int64(be.Uint16(d[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return "", 0, false
	}
	pages := int64(be.Uint32(d[28:32]))
	desc := fmt.Sprintf("SQLite 3 database, page size %d", ps)
	if pages > 0 {
		desc += fmt.Sprintf(", %d page%s", pages, plural(int(pages), "", "s"))
	}
	return desc, ps * pages, true
}

// ------------------------------------------------------------- firmware

func checkSquashFS(order binary.ByteOrder) checkFunc {
	return func(d []byte) (string, int64, bool) {
		if len(d) < 96 {
			return "", 0, false
		}
		major, minor := order.Uint16(d[28:30]), order.Uint16(d[30:32])
		if major < 1 || major > 4 {
			return "", 0, false
		}
		var size int64
		var comp string
		if major == 4 {
			size = int64(order.Uint64(d[40:48]))
			switch order.Uint16(d[20:22]) {
			case 1:
				comp = "gzip"
			case 2:
				comp = "lzma"
			case 3:
				comp = "lzo"
			case 4:
				comp = "xz"
			case 5:
				comp = "lz4"
			case 6:
				comp = "zstd"
			default:
				return "", 0, false
			}
		} else {
			size = int64(order.Uint32(d[8:12]))
		}
		endian := "little-endian"
		if order == be {
			endian = "big-endian"
		}
		desc := fmt.Sprintf("SquashFS filesystem %d.%d, %s", major, minor, endian)
		if comp != "" {
			desc += ", " + comp
		}
		return desc, size, true
	}
}

func checkCramFS(order binary.ByteOrder) checkFunc {
	return func(d []byte) (string, int64, bool) {
		if len(d) < 64 || string(d[16:32]) != "Compressed ROMFS" {
			return "", 0, false
		}
		return "CramFS filesystem", int64(order.Uint32(d[4:8])), true
	}
}

func checkUImage(d []byte) (string, int64, bool) {
	if len(d) < 64 {
		return "", 0, false
	}
	hdr := make([]byte, 64)
	copy(hdr, d[:64])
	want := be.Uint32(hdr[4:8])
	hdr[4], hdr[5], hdr[6], hdr[7] = 0, 0, 0, 0
	if crc32.ChecksumIEEE(hdr) != want {
		return "", 0, false
	}
	name := string(bytes.TrimRight(d[32:64], "\x00"))
	return fmt.Sprintf("U-Boot legacy image %q", name), 64 + int64(be.Uint32(d[12:16])), true
}

func checkUBI(d []byte) (string, int64, bool) {
	if len(d) < 64 || d[4] != 1 {
		return "", 0, false
	}
	return "UBI erase count header", 0, true
}

func checkUBIFS(d []byte) (string, int64, bool) {
	if len(d) < 24 || d[20] > 12 {
		return "", 0, false
	}
	return "UBIFS node", 0, true
}

func checkJFFS2(order binary.ByteOrder) checkFunc {
	return func(d []byte) (string, int64, bool) {
		if len(d) < 12 {
			return "", 0, false
		}
		nt := order.Uint16(d[2:4])
		if nt != 0xE001 && nt != 0xE002 && nt != 0x2003 && nt != 0x2004 && nt != 0xE006 && nt != 0xE008 && nt != 0xE009 {
			return "", 0, false
		}
		// The header CRC covers the first 8 bytes, with JFFS2's CRC32 variant
		// (no final inversion).
		crc := ^crc32.Update(0xFFFFFFFF, crc32.IEEETable, d[:8])
		if crc != order.Uint32(d[8:12]) {
			return "", 0, false
		}
		endian := "little-endian"
		if order == be {
			endian = "big-endian"
		}
		return "JFFS2 filesystem, " + endian, 0, true
	}
}

func checkDTB(d []byte) (string, int64, bool) {
	if len(d) < 40 {
		return "", 0, false
	}
	size := int64(be.Uint32(d[4:8]))
	ver := be.Uint32(d[20:24])
	if size < 40 || ver < 1 || ver > 17 {
		return "", 0, false
	}
	return fmt.Sprintf("Flattened device tree, version %d", ver), size, true
}

// --------------------------------------------------------------- helpers

func parseOctal(b []byte) (int64, bool) {
	b = bytes.Trim(b, " \x00")
	if len(b) == 0 {
		return 0, false
	}
	var v int64
	for _, c := range b {
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int64(c-'0')
	}
	return v, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
