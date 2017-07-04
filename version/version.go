package version

// GitCommit defines the git commit that was compiled. This will be filled in by
// the compiler.
var GitCommit string

// Version defines the main version number that is being run at the moment. This
// will be filled by the compiler.
var Version = "0.0.0-no-proper-build"
