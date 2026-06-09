package metadata

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// EXIF tags - common ones
var exifTags = map[uint16]string{
	// Image tags
	0x0100: "ImageWidth",
	0x0101: "ImageHeight",
	0x0102: "BitsPerSample",
	0x0103: "Compression",
	0x0106: "PhotometricInterpretation",
	0x010E: "ImageDescription",
	0x010F: "Make",
	0x0110: "Model",
	0x0112: "Orientation",
	0x011A: "XResolution",
	0x011B: "YResolution",
	0x011C: "PlanarConfiguration",
	0x0128: "ResolutionUnit",
	0x0131: "Software",
	0x0132: "DateTime",
	0x013B: "Artist",
	0x0213: "YCbCrPositioning",
	0x8769: "ExifIFDPointer",
	0x8825: "GPSInfoIFDPointer",
	
	// EXIF sub-tags
	0x829A: "ExposureTime",
	0x829D: "FNumber",
	0x8822: "ExposureProgram",
	0x8827: "ISOSpeedRatings",
	0x9000: "ExifVersion",
	0x9003: "DateTimeOriginal",
	0x9004: "DateTimeDigitized",
	0x9201: "ShutterSpeedValue",
	0x9202: "ApertureValue",
	0x9203: "BrightnessValue",
	0x9204: "ExposureBiasValue",
	0x9207: "MeteringMode",
	0x9209: "Flash",
	0x920A: "FocalLength",
	0xA001: "ColorSpace",
	0xA002: "PixelXDimension",
	0xA003: "PixelYDimension",
	0xA405: "FocalLengthIn35mmFilm",
	0xA420: "ImageUniqueID",
	0xA430: "CameraOwnerName",
	0xA431: "BodySerialNumber",
	0xA432: "LensInfo",
	0xA433: "LensMake",
	0xA434: "LensModel",
	
	// GPS tags
	0x0000: "GPSVersionID",
	0x0001: "GPSLatitudeRef",
	0x0002: "GPSLatitude",
	0x0003: "GPSLongitudeRef",
	0x0004: "GPSLongitude",
	0x0005: "GPSAltitudeRef",
	0x0006: "GPSAltitude",
	0x0007: "GPSTimeStamp",
	0x001D: "GPSDateStamp",
}

// EXIF data types
const (
	exifTypeByte     = 1
	exifTypeAscii    = 2
	exifTypeShort    = 3
	exifTypeLong     = 4
	exifTypeRational = 5
	exifTypeSByte    = 6
	exifTypeUndefined = 7
	exifTypeSShort   = 8
	exifTypeSLong    = 9
	exifTypeSRational = 10
	exifTypeFloat    = 11
	exifTypeDouble   = 12
)

// ExtractEXIF extracts EXIF metadata from a JPEG/TIFF file
func ExtractEXIF(filePath string) (*EXIFResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read header
	header := make([]byte, 4)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Check if JPEG
	if header[0] != 0xFF || header[1] != 0xD8 {
		return nil, fmt.Errorf("not a JPEG file")
	}

	// Find EXIF marker
	var exifData []byte
	for {
		var marker [2]byte
		if _, err := io.ReadFull(f, marker[:]); err != nil {
			break
		}

		if marker[0] != 0xFF {
			break
		}

		if marker[1] == 0xE1 { // EXIF marker
			// Read length
			var length [2]byte
			if _, err := io.ReadFull(f, length[:]); err != nil {
				break
			}
			Len := binary.BigEndian.Uint16(length[:])

			// Read EXIF data
			exifData = make([]byte, Len-2)
			if _, err := io.ReadFull(f, exifData); err != nil {
				break
			}
			break
		} else if marker[1] == 0xDA { // Start of scan
			break
		} else {
			// Skip this marker
			var length [2]byte
			if _, err := io.ReadFull(f, length[:]); err != nil {
				break
			}
			Len := binary.BigEndian.Uint16(length[:])
			if _, err := io.ReadFull(f, make([]byte, Len-2)); err != nil {
				break
			}
		}
	}

	if len(exifData) < 8 {
		return nil, fmt.Errorf("no EXIF data found")
	}

	// Parse EXIF header
	result := &EXIFResult{
		Tags:     make(map[string]interface{}),
		Warnings: []string{},
	}

	// Check byte order
	var byteOrder binary.ByteOrder
	if exifData[0] == 'I' && exifData[1] == 'I' {
		byteOrder = binary.LittleEndian
	} else if exifData[0] == 'M' && exifData[1] == 'M' {
		byteOrder = binary.BigEndian
	} else {
		return nil, fmt.Errorf("invalid EXIF byte order")
	}

	// Parse IFD
	tags, err := parseIFD(exifData[6:], byteOrder, exifData)
	if err != nil {
		return nil, err
	}

	result.Tags = tags
	return result, nil
}

// parseIFD parses an EXIF IFD
func parseIFD(data []byte, byteOrder binary.ByteOrder, allData []byte) (map[string]interface{}, error) {
	tags := make(map[string]interface{})

	if len(data) < 2 {
		return tags, nil
	}

	// Number of entries
	numEntries := byteOrder.Uint16(data[:2])

	for i := 0; i < int(numEntries) && len(data) > 2+i*12+12; i++ {
		offset := 2 + i*12
		tag := byteOrder.Uint16(data[offset : offset+2])
		dataType := byteOrder.Uint16(data[offset+2 : offset+4])
		dataLen := byteOrder.Uint32(data[offset+4 : offset+8])
		valueOffset := byteOrder.Uint32(data[offset+8 : offset+12])

		// Get tag name
		tagName, ok := exifTags[tag]
		if !ok {
			tagName = fmt.Sprintf("Tag_0x%04X", tag)
		}

		// Parse value
		value, err := parseEXIFValue(dataType, dataLen, valueOffset, data, byteOrder, allData)
		if err != nil {
			continue
		}

		tags[tagName] = value
	}

	return tags, nil
}

// parseEXIFValue parses an EXIF value
func parseEXIFValue(dataType uint16, dataLen uint32, valueOffset uint32, data []byte, byteOrder binary.ByteOrder, allData []byte) (interface{}, error) {
	// Calculate actual offset in allData
	actualOffset := valueOffset

	switch dataType {
	case exifTypeByte:
		if dataLen == 1 {
			return data[actualOffset], nil
		}
		return data[actualOffset : actualOffset+dataLen], nil

	case exifTypeAscii:
		if actualOffset+dataLen <= uint32(len(allData)) {
			s := string(allData[actualOffset : actualOffset+dataLen])
			return strings.TrimRight(s, "\x00"), nil
		}

	case exifTypeShort:
		if dataLen == 1 {
			return byteOrder.Uint16(allData[actualOffset : actualOffset+2]), nil
		}

	case exifTypeLong:
		if dataLen == 1 {
			return byteOrder.Uint32(allData[actualOffset : actualOffset+4]), nil
		}

	case exifTypeRational:
		if actualOffset+8 <= uint32(len(allData)) {
			num := byteOrder.Uint32(allData[actualOffset : actualOffset+4])
			denom := byteOrder.Uint32(allData[actualOffset+4 : actualOffset+8])
			if denom != 0 {
				return float64(num) / float64(denom), nil
			}
			return 0, nil
		}

	case exifTypeUndefined:
		if dataLen == 1 {
			return data[actualOffset], nil
		}
		return data[actualOffset : actualOffset+dataLen], nil

	case exifTypeSByte:
		return int8(data[actualOffset]), nil

	case exifTypeSShort:
		return int16(byteOrder.Uint16(allData[actualOffset:actualOffset+2])), nil

	case exifTypeSLong:
		return int32(byteOrder.Uint32(allData[actualOffset:actualOffset+4])), nil

	case exifTypeSRational:
		if actualOffset+8 <= uint32(len(allData)) {
			num := int32(byteOrder.Uint32(allData[actualOffset : actualOffset+4]))
			denom := int32(byteOrder.Uint32(allData[actualOffset+4 : actualOffset+8]))
			if denom != 0 {
				return float64(num) / float64(denom), nil
			}
			return 0, nil
		}

	case exifTypeFloat:
		bits := byteOrder.Uint32(allData[actualOffset : actualOffset+4])
		return float32(bits), nil

	case exifTypeDouble:
		bits := byteOrder.Uint64(allData[actualOffset : actualOffset+8])
		return float64(bits), nil
	}

	return nil, fmt.Errorf("unsupported data type %d", dataType)
}

// FormatEXIFResult formats EXIF result for display
func FormatEXIFResult(result *EXIFResult) string {
	if result == nil || len(result.Tags) == 0 {
		return "No EXIF data found"
	}

	var sb strings.Builder
	sb.WriteString("EXIF Metadata:\n")

	// Camera info
	if make, ok := result.Tags["Make"]; ok {
		sb.WriteString(fmt.Sprintf("  Camera Make: %v\n", make))
	}
	if model, ok := result.Tags["Model"]; ok {
		sb.WriteString(fmt.Sprintf("  Camera Model: %v\n", model))
	}
	if software, ok := result.Tags["Software"]; ok {
		sb.WriteString(fmt.Sprintf("  Software: %v\n", software))
	}

	// Image info
	if width, ok := result.Tags["PixelXDimension"]; ok {
		sb.WriteString(fmt.Sprintf("  Width: %v\n", width))
	}
	if height, ok := result.Tags["PixelYDimension"]; ok {
		sb.WriteString(fmt.Sprintf("  Height: %v\n", height))
	}

	// Exposure info
	if exposure, ok := result.Tags["ExposureTime"]; ok {
		sb.WriteString(fmt.Sprintf("  Exposure: %v\n", exposure))
	}
	if fnumber, ok := result.Tags["FNumber"]; ok {
		sb.WriteString(fmt.Sprintf("  F-Number: %v\n", fnumber))
	}
	if iso, ok := result.Tags["ISOSpeedRatings"]; ok {
		sb.WriteString(fmt.Sprintf("  ISO: %v\n", iso))
	}
	if focal, ok := result.Tags["FocalLength"]; ok {
		sb.WriteString(fmt.Sprintf("  Focal Length: %v\n", focal))
	}

	// Date info
	if datetime, ok := result.Tags["DateTime"]; ok {
		sb.WriteString(fmt.Sprintf("  Date: %v\n", datetime))
	}
	if datetimeOriginal, ok := result.Tags["DateTimeOriginal"]; ok {
		sb.WriteString(fmt.Sprintf("  Date Original: %v\n", datetimeOriginal))
	}

	// GPS info
	if lat, ok := result.Tags["GPSLatitude"]; ok {
		sb.WriteString(fmt.Sprintf("  GPS Latitude: %v\n", lat))
	}
	if latRef, ok := result.Tags["GPSLatitudeRef"]; ok {
		sb.WriteString(fmt.Sprintf("  GPS Latitude Ref: %v\n", latRef))
	}
	if lon, ok := result.Tags["GPSLongitude"]; ok {
		sb.WriteString(fmt.Sprintf("  GPS Longitude: %v\n", lon))
	}
	if lonRef, ok := result.Tags["GPSLongitudeRef"]; ok {
		sb.WriteString(fmt.Sprintf("  GPS Longitude Ref: %v\n", lonRef))
	}
	if alt, ok := result.Tags["GPSAltitude"]; ok {
		sb.WriteString(fmt.Sprintf("  GPS Altitude: %v\n", alt))
	}

	// Other tags
	sb.WriteString("\n  Other Tags:\n")
	for key, value := range result.Tags {
		if !strings.HasPrefix(key, "GPS") && key != "Make" && key != "Model" && key != "Software" &&
			key != "PixelXDimension" && key != "PixelYDimension" && key != "ExposureTime" &&
			key != "FNumber" && key != "ISOSpeedRatings" && key != "FocalLength" &&
			key != "DateTime" && key != "DateTimeOriginal" {
			sb.WriteString(fmt.Sprintf("    %s: %v\n", key, value))
		}
	}

	return sb.String()
}
