package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepairJPEGWithSOIAndEOI exercises the "missing EOI" branch when the file
// already starts with SOI.
func TestRepairJPEGWithSOIAndEOI(t *testing.T) {
	// JPEG with SOI but no EOI: first 2 bytes 0xFF 0xD8
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	result, err := Repair(data, "test.jpg", &Options{NoBackup: true, DryRun: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
	if result.Strategy != "add_eoi_marker" {
		t.Errorf("expected strategy add_eoi_marker, got %s", result.Strategy)
	}
	if result.RepairedSize != int64(len(data)+2) {
		t.Errorf("expected repaired size %d, got %d", len(data)+2, result.RepairedSize)
	}
}

// TestRepairPDFWithHeader exercises the "missing %%EOF" branch.
func TestRepairPDFWithHeader(t *testing.T) {
	data := []byte("%PDF-1.7\r\n1 0 obj\n<< /Type /Catalog >>\nendobj")
	result, err := Repair(data, "test.pdf", &Options{NoBackup: true, DryRun: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
	if result.Strategy != "add_pdf_eof" {
		t.Errorf("expected strategy add_pdf_eof, got %s", result.Strategy)
	}
}

// TestRepairPDFWithoutHeader exercises the "missing header" branch by
// forcing TargetFormat to "pdf" (otherwise detectFormat would reject the data).
func TestRepairPDFWithoutHeader(t *testing.T) {
	// No %PDF header
	data := []byte("this is not a pdf but we try")
	result, err := Repair(data, "test.pdf", &Options{NoBackup: true, DryRun: true, TargetFormat: "pdf"})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
	if result.Strategy != "add_pdf_header" {
		t.Errorf("expected strategy add_pdf_header, got %s", result.Strategy)
	}
}

// TestRepairJPEGCompleteWithSOIAndEOI returns nil from the inner repair
// function (no repair needed), exercising the "no repair needed" branch.
func TestRepairJPEGCompleteWithSOIAndEOI(t *testing.T) {
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9}
	repaired, strategy := repairJPEG(data)
	if repaired != nil {
		t.Error("expected nil for complete JPEG")
	}
	if strategy != "" {
		t.Errorf("expected empty strategy, got %s", strategy)
	}
}

// TestRepairPDFCompleteWithEOF returns nil (no repair needed).
func TestRepairPDFCompleteWithEOF(t *testing.T) {
	data := []byte("%PDF-1.7\r\n%%EOF\r\n")
	repaired, strategy := repairPDF(data)
	if repaired != nil {
		t.Error("expected nil for complete PDF")
	}
	if strategy != "" {
		t.Errorf("expected empty strategy, got %s", strategy)
	}
}

// TestRepairZIPCompleteWithEOCD returns nil (no repair needed).
func TestRepairZIPCompleteWithEOCD(t *testing.T) {
	// ZIP with EOCD present
	data := []byte{
		0x50, 0x4B, 0x03, 0x04, // local file header
		0x50, 0x4B, 0x05, 0x06, // EOCD
	}
	repaired, strategy := repairZIP(data)
	if repaired != nil {
		t.Error("expected nil for complete ZIP")
	}
	if strategy != "" {
		t.Errorf("expected empty strategy, got %s", strategy)
	}
}

// TestRepairCreatesBackup verifies that backup creation runs when not disabled
// and the file is written.
func TestRepairCreatesBackup(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "broken.jpg")
	// JPEG with no SOI marker. detectFormat rejects this, so we force
	// TargetFormat to "jpeg" to exercise the JPEG repair path and the
	// backup code.
	if err := os.WriteFile(src, []byte{0xFF, 0xE0, 0x00, 0x10}, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}

	result, err := Repair(data, src, &Options{DryRun: false, NoBackup: false, TargetFormat: "jpeg"})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if !result.BackupCreated {
		t.Error("expected BackupCreated to be true")
	}

	// Verify backup file exists
	backupPath := src + ".bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("expected backup file to exist")
	}

	// Verify the changes log includes the backup
	found := false
	for _, c := range result.Changes {
		if strings.Contains(c, "Backup created") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected changes to mention backup")
	}
}

// TestRepairWritesOutput verifies the file is written when not in dry-run.
func TestRepairWritesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	out := filepath.Join(tmpDir, "fixed.jpg")
	// Data that triggers JPEG repair when TargetFormat is forced.
	data := []byte{0xFF, 0xE0, 0x00, 0x10}

	result, err := Repair(data, "ignored.jpg", &Options{
		OutputPath:  out,
		DryRun:      false,
		NoBackup:    true,
		TargetFormat: "jpeg",
	})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}

	// Verify output file exists and starts with SOI 0xFF 0xD8
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(written) < 2 || written[0] != 0xFF || written[1] != 0xD8 {
		t.Errorf("expected output to start with SOI marker, got %x", written[:2])
	}
}

// TestRepairWritesOutputWriteError simulates a write failure with an
// impossible path. The error should be wrapped.
func TestRepairWritesOutputWriteError(t *testing.T) {
	// /dev/null/subdir/... is not writable
	_, err := Repair(
		[]byte{0xFF, 0xE0, 0x00, 0x10},
		"src.jpg",
		&Options{
			OutputPath:  "/dev/null/cannot/write/here.jpg",
			DryRun:      false,
			NoBackup:    true,
			TargetFormat: "jpeg",
		},
	)
	if err == nil {
		t.Error("expected error when output path is invalid")
	}
}

// TestRepairPNGWithIHDRExercisesReconstruct exercises the "reconstruct from
// chunks" branch in repairPNG (data has no signature but contains IHDR).
func TestRepairPNGWithIHDRExercisesReconstruct(t *testing.T) {
	// PNG without signature but with IHDR
	data := []byte{
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
	}
	repaired, strategy := repairPNG(data)
	if repaired == nil {
		t.Fatal("expected non-nil repair result")
	}
	if strategy != "reconstruct_from_chunks" {
		t.Errorf("expected strategy reconstruct_from_chunks, got %s", strategy)
	}
	// Verify it now starts with the PNG signature
	if len(repaired) < 8 {
		t.Fatal("repaired data too short")
	}
	if repaired[0] != 0x89 || repaired[1] != 0x50 || repaired[2] != 0x4E || repaired[3] != 0x47 {
		t.Error("expected repaired data to start with PNG signature")
	}
}

// TestRepairPNGGenerateMinimal exercises the "generate minimal header" branch
// when the data has no signature and no IHDR chunk.
func TestRepairPNGGenerateMinimal(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD} // no PNG signature, no IHDR
	repaired, strategy := repairPNG(data)
	if repaired == nil {
		t.Fatal("expected non-nil repair result")
	}
	if strategy != "generate_minimal_header" {
		t.Errorf("expected strategy generate_minimal_header, got %s", strategy)
	}
}

// TestRepairPNGSigAndIEND exercises the case where PNG has the signature and
// IEND, so no repair is needed.
func TestRepairPNGSigAndIEND(t *testing.T) {
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x45, 0x4E, 0x44, // IEND
		0xAE, 0x42, 0x60, 0x82,
	}
	repaired, strategy := repairPNG(data)
	if repaired != nil {
		t.Error("expected nil for complete PNG")
	}
	if strategy != "" {
		t.Errorf("expected empty strategy, got %s", strategy)
	}
}

// TestRepairWithOptsNil ensures that a nil options pointer is handled
// gracefully (defaults to "auto" strategy).
func TestRepairWithOptsNil(t *testing.T) {
	result, err := Repair([]byte("not a real file"), "test.bin", nil)
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Strategy != "" {
		t.Errorf("expected empty strategy for unknown format, got %s", result.Strategy)
	}
	if len(result.Warnings) == 0 {
		t.Error("expected at least one warning for unknown format")
	}
}
