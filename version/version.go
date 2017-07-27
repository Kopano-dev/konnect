package version

// BuildDate defines the date when build/compile was run. This will be filled in
// by the compiler.
var BuildDate string

// Version defines the main version number that is being run at the moment. This
// will be filled by the compiler.
var Version = "0.0.0-no-proper-build"
