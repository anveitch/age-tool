// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package desktop

import (
	"fmt"
	"strings"
)

// ─── Quoting ────────────────────────────────────────────────────────────────

// desktopExec builds an Exec= value for a desktop entry (launcher, KDE
// service menu): the program quoted per the Desktop Entry spec, then the
// arguments, which must already be safe (fixed words and % codes).
func desktopExec(exe string, args ...string) string {
	return escapeDesktopValue(quoteExecArg(exe)) + " " + strings.Join(args, " ")
}

// quoteExecArg quotes one Exec argument as the Desktop Entry spec
// requires: inside double quotes, the characters " ` $ and \ are escaped
// with a backslash. Plain arguments are left as they are.
func quoteExecArg(arg string) string {
	if !strings.ContainsAny(arg, " \t\"'\\><~|&;$*?#()`=") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range arg {
		if strings.ContainsRune("\"`$\\", c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteByte('"')
	return b.String()
}

// escapeDesktopValue applies the desktop file's own string escaping, which
// is undone before the Exec quoting above is read: a backslash is written
// as two.
func escapeDesktopValue(s string) string {
	return strings.ReplaceAll(s, `\`, `\\`)
}

// shellQuote quotes s for a POSIX shell or GLib's shell-style parser (used
// by Nemo and Thunar): wrapped in single quotes, with any single quote
// written as '\”.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// xmlEscape escapes text for an XML element.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// ─── File contents ──────────────────────────────────────────────────────────

// menuLabel returns the right-click label for an action ("encrypt" or
// "decrypt").
func menuLabel(action string) string {
	if action == "decrypt" {
		return DecryptMenu
	}
	return EncryptMenu
}

// launcherEntry is the app menu entry. Files opened with it (double-click,
// or "Open With") are passed straight to the program, which decrypts .age
// files and encrypts anything else.
func (in Integration) launcherEntry() []byte {
	return fmt.Appendf(nil, `[Desktop Entry]
Type=Application
Name=%s
GenericName=%s
Comment=%s
Exec=%s
Icon=%s
Terminal=false
Categories=Utility;Security;
Keywords=encrypt;decrypt;age;privacy;security;
MimeType=%s;
StartupNotify=true
`, AppName, GenericName, Comment, desktopExec(in.Exe, "%F"), AppID, MimeType)
}

// mimePackageXML defines the .age file type: by its extension, and by the
// "age-encryption.org/v1" header every age file starts with.
func mimePackageXML() []byte {
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!-- Added by age-tool -->
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="%s">
    <comment>Encrypted file (age)</comment>
    <icon name="%s"/>
    <glob pattern="*.age"/>
    <magic priority="50">
      <match type="string" offset="0" value="age-encryption.org/v1"/>
    </magic>
  </mime-type>
</mime-info>
`, MimeType, mimeIcon)
}

// nautilusScript is a Nautilus Scripts-menu entry. Nautilus runs it in the
// files' folder with the selected file names as arguments.
func (in Integration) nautilusScript(action string) []byte {
	return fmt.Appendf(nil, `#!/bin/sh
# Added by age-tool: right-click > Scripts > %s
exec %s %s -- "$@"
`, menuLabel(action), shellQuote(in.Exe), action)
}

// dolphinMenu is a KDE service menu: one right-click entry, shown for all
// files (encrypt) or only .age files (decrypt).
func (in Integration) dolphinMenu(action string) []byte {
	mimeTypes := "all/allfiles;"
	if action == "decrypt" {
		mimeTypes = MimeType + ";"
	}
	return fmt.Appendf(nil, `[Desktop Entry]
Type=Service
X-KDE-ServiceTypes=KonqPopupMenu/Plugin
MimeType=%s
Actions=%s;
X-KDE-Priority=TopLevel

[Desktop Action %s]
Name=%s
Icon=%s
Exec=%s
`, mimeTypes, action, action, menuLabel(action), AppID, desktopExec(in.Exe, action, "--", "%F"))
}

// nemoAction is a Nemo right-click action, shown for any files (encrypt)
// or only .age files (decrypt), never for folders.
func (in Integration) nemoAction(action string) []byte {
	extensions := "nodirs;"
	if action == "decrypt" {
		extensions = "age;"
	}
	return fmt.Appendf(nil, `[Nemo Action]
Name=%s
Comment=%s
Exec=%s %s -- %%F
Icon-Name=%s
Selection=notnone
Extensions=%s
`, menuLabel(action), Comment, shellQuote(in.Exe), action, AppID, extensions)
}

// thunarAction is one Thunar custom action, shown for any files (encrypt)
// or only .age files (decrypt), never for folders.
func (in Integration) thunarAction(action string) string {
	pattern := "*"
	if action == "decrypt" {
		pattern = "*.age"
	}
	return fmt.Sprintf(`<action>
	<icon>%s</icon>
	<name>%s</name>
	<unique-id>%s%s</unique-id>
	<command>%s %s -- %%F</command>
	<description>%s</description>
	<patterns>%s</patterns>
	<audio-files/>
	<image-files/>
	<other-files/>
	<text-files/>
	<video-files/>
</action>
`, AppID, xmlEscape(menuLabel(action)), thunarIDPrefix, action, xmlEscape(shellQuote(in.Exe)), action, xmlEscape(Comment), pattern)
}

// AppImageEntry is the desktop entry stored inside the AppImage. AppImage
// tools (and appimaged-style integrators) read it to find the app's name,
// icon and file types. Its Exec is the bare program name, as the AppImage
// format requires; the menus age-tool installs itself (Install) use the
// AppImage's real path instead.
func AppImageEntry() []byte {
	return Integration{Exe: ExeName}.launcherEntry()
}
