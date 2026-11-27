// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

// Version is the age-tool release version, shared by the CLI and the
// desktop app so both always report the same number. release.sh rewrites
// this line when making a release; between releases it carries a "-dev"
// suffix so development builds are never mistaken for a release.
const Version = "2.0.0"
