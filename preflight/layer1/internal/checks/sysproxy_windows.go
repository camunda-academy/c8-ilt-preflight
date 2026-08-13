//go:build windows

package checks

import (
	"strings"
	"syscall"
	"unsafe"
)

// wininetKey is where Windows keeps the per-user proxy configuration that
// WinINET-based clients follow -- .NET's HttpClient among them. It is read from
// HKEY_CURRENT_USER because the settings are per-user, which is also why two
// participants on identically-built machines can behave differently.
const wininetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// DetectSystemProxy reads the OS proxy configuration.
//
// Implemented with the standard library's syscall package rather than
// golang.org/x/sys/windows/registry: this binary is built with no external
// modules and no CGO so a customer's security team can audit the source and
// reproduce the build, and pulling in a dependency for four registry reads
// would trade that away.
//
// Every failure path returns "nothing configured" rather than an error. This is
// diagnostic context, so a locked-down machine that refuses the read must never
// be able to fail the run.
func DetectSystemProxy() SystemProxy {
	s := SystemProxy{Supported: true}

	path, err := syscall.UTF16PtrFromString(wininetKey)
	if err != nil {
		return s
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, path, 0, syscall.KEY_READ, &key); err != nil {
		return s
	}
	defer syscall.RegCloseKey(key)

	// ProxyEnable gates the static ProxyServer setting only. An auto-config
	// script is a separate mechanism that applies whether or not that flag is
	// set, so a PAC URL alone still counts as a configured proxy -- treating
	// ProxyEnable as the single switch would miss the common enterprise case.
	enabled := regDWORD(key, "ProxyEnable") == 1
	s.PACURL = strings.TrimSpace(regString(key, "AutoConfigURL"))
	if enabled {
		s.Server = strings.TrimSpace(regString(key, "ProxyServer"))
		s.Bypass = strings.TrimSpace(regString(key, "ProxyOverride"))
	}
	s.Configured = s.Server != "" || s.PACURL != ""
	return s
}

// regString reads a string value, returning "" when absent or not a string.
func regString(key syscall.Handle, name string) string {
	buf, typ, ok := regValue(key, name)
	if !ok || (typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ) {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// regDWORD reads a numeric value, returning 0 when absent or not a DWORD.
func regDWORD(key syscall.Handle, name string) uint32 {
	buf, typ, ok := regValue(key, name)
	if !ok || typ != syscall.REG_DWORD || len(buf) == 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(&buf[0]))
}

// regValue reads one value as raw UTF-16 words plus its type. The buffer is
// sized from the first call's reported length; the extra word leaves room for a
// terminating NUL the API does not always include, and guarantees index 0 is
// addressable for the DWORD case.
func regValue(key syscall.Handle, name string) ([]uint16, uint32, bool) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, false
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, n, nil, &typ, nil, &size); err != nil {
		return nil, 0, false
	}
	buf := make([]uint16, size/2+1)
	if err := syscall.RegQueryValueEx(key, n, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return nil, 0, false
	}
	return buf, typ, true
}
