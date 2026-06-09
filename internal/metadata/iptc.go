package metadata

import (
	"fmt"
	"os"
	"strings"
)

// IPTC tags
var iptcTags = map[byte]string{
	0x00: "RecordVersion",
	0x05: "ObjectName",
	0x07: "EditStatus",
	0x0A: "Urgency",
	0x0C: "Category",
	0x0F: "Fixed",
	0x14: "SpecialInstructions",
	0x1A: "DateCreated",
	0x1B: "TimeCreated",
	0x1C: "DigitalCreationDate",
	0x1D: "DigitalCreationTime",
	0x1E: "OriginatingProgram",
	0x1F: "ProgramVersion",
	0x20: "Byline",
	0x21: "BylineTitle",
	0x22: "City",
	0x23: "SubLocation",
	0x24: "Province",
	0x25: "CountryCode",
	0x26: "Country",
	0x28: "OriginalTransmissionReference",
	0x2A: "Headline",
	0x2B: "Credit",
	0x2C: "Source",
	0x2D: "CopyrightNotice",
	0x30: "Contact",
	0x32: "Caption",
	0x33: "Writer",
	0x37: "ImageOrientation",
	0x3C: "LanguageID",
	0x50: "Keywords",
	0x5D: "ReleaseDate",
	0x5E: "ReleaseTime",
	0x64: "SubFile",
	0x65: "OriginalImageID",
	0x66: "OriginalFileName",
	0x67: "DigitalOriginalFileID",
	0x69: "ResourceLink",
	0x6B: "AlternateFileName",
	0x6C: "AlternateFileID",
	0x76: "CameraImageGUID",
	0x7D: "ImageSupplierID",
	0x7E: "ImageSupplierName",
	0x7F: "ImageSupplierLogo",
	0x82: "CopyrightNotice",
	0x83: "LicenseURL",
}

// ExtractIPTC extracts IPTC metadata from a file
func ExtractIPTC(filePath string) (map[string]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read file content
	content := make([]byte, 1024*1024) // Read up to 1MB
	n, err := f.Read(content)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	content = content[:n]

	// Look for IPTC marker (0x1C)
	tags := make(map[string]string)

	for i := 0; i < len(content)-4; i++ {
		if content[i] == 0x1C { // IPTC marker
			_ = content[i+1] // recordType
			dataSet := content[i+2]
			dataLen := int(content[i+3])<<8 | int(content[i+4])

			// Get tag name
			tagName, ok := iptcTags[dataSet]
			if !ok {
				tagName = fmt.Sprintf("DataSet_%02X", dataSet)
			}

			// Extract value
			if i+5+dataLen <= len(content) {
				value := string(content[i+5 : i+5+dataLen])
				tags[tagName] = strings.TrimRight(value, "\x00")
			}

			// Skip to next marker
			i += 4 + dataLen
		}
	}

	if len(tags) == 0 {
		return nil, fmt.Errorf("no IPTC data found")
	}

	return tags, nil
}

// FormatIPTCData formats IPTC data for display
func FormatIPTCData(tags map[string]string) string {
	if len(tags) == 0 {
		return "No IPTC data found"
	}

	var sb strings.Builder
	sb.WriteString("IPTC Metadata:\n")

	// Object info
	if name, ok := tags["ObjectName"]; ok {
		sb.WriteString(fmt.Sprintf("  Title: %s\n", name))
	}
	if caption, ok := tags["Caption"]; ok {
		sb.WriteString(fmt.Sprintf("  Caption: %s\n", caption))
	}
	if headline, ok := tags["Headline"]; ok {
		sb.WriteString(fmt.Sprintf("  Headline: %s\n", headline))
	}
	if keywords, ok := tags["Keywords"]; ok {
		sb.WriteString(fmt.Sprintf("  Keywords: %s\n", keywords))
	}

	// Creator info
	if byline, ok := tags["Byline"]; ok {
		sb.WriteString(fmt.Sprintf("  Byline: %s\n", byline))
	}
	if title, ok := tags["BylineTitle"]; ok {
		sb.WriteString(fmt.Sprintf("  Byline Title: %s\n", title))
	}

	// Location info
	if city, ok := tags["City"]; ok {
		sb.WriteString(fmt.Sprintf("  City: %s\n", city))
	}
	if sublocation, ok := tags["SubLocation"]; ok {
		sb.WriteString(fmt.Sprintf("  Sub-Location: %s\n", sublocation))
	}
	if province, ok := tags["Province"]; ok {
		sb.WriteString(fmt.Sprintf("  Province: %s\n", province))
	}
	if country, ok := tags["Country"]; ok {
		sb.WriteString(fmt.Sprintf("  Country: %s\n", country))
	}
	if countryCode, ok := tags["CountryCode"]; ok {
		sb.WriteString(fmt.Sprintf("  Country Code: %s\n", countryCode))
	}

	// Date info
	if dateCreated, ok := tags["DateCreated"]; ok {
		sb.WriteString(fmt.Sprintf("  Date Created: %s\n", dateCreated))
	}
	if timeCreated, ok := tags["TimeCreated"]; ok {
		sb.WriteString(fmt.Sprintf("  Time Created: %s\n", timeCreated))
	}
	if digitalDate, ok := tags["DigitalCreationDate"]; ok {
		sb.WriteString(fmt.Sprintf("  Digital Creation Date: %s\n", digitalDate))
	}
	if digitalTime, ok := tags["DigitalCreationTime"]; ok {
		sb.WriteString(fmt.Sprintf("  Digital Creation Time: %s\n", digitalTime))
	}

	// Copyright
	if copyright, ok := tags["CopyrightNotice"]; ok {
		sb.WriteString(fmt.Sprintf("  Copyright: %s\n", copyright))
	}
	if source, ok := tags["Source"]; ok {
		sb.WriteString(fmt.Sprintf("  Source: %s\n", source))
	}
	if credit, ok := tags["Credit"]; ok {
		sb.WriteString(fmt.Sprintf("  Credit: %s\n", credit))
	}

	return sb.String()
}
