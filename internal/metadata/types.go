package metadata

// EXIFResult represents EXIF extraction result
type EXIFResult struct {
	Tags     map[string]interface{}
	Warnings []string
}

// MetadataResult represents metadata extraction result
type MetadataResult struct {
	Format string
	Data   map[string]interface{}
}
