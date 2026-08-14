# Cross-compiles the Layer 1 preflight binary for all target platforms
# (windows/amd64, darwin/amd64, darwin/arm64, linux/amd64) and writes
# SHA-256 checksums into /preflight/releases.
# Stdlib only -- no CGO, no external modules, so a customer security team
# can audit the source directly.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReleasesDir = Join-Path $ScriptDir "..\releases"
$Version = if ($env:PREFLIGHT_VERSION) { $env:PREFLIGHT_VERSION } else { "0.2" }

New-Item -ItemType Directory -Force -Path $ReleasesDir | Out-Null
Set-Location $ScriptDir

$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = "" },
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = "" }
)

foreach ($t in $Targets) {
    $out = "preflight-$($t.GOOS)-$($t.GOARCH)$($t.Ext)"
    Write-Host "Building $out ..."
    $env:CGO_ENABLED = "0"
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    & go build -ldflags "-s -w -X main.ToolVersion=$Version" -o (Join-Path $ReleasesDir $out) ./cmd/preflight
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host "Computing checksums ..."
$ChecksumFile = Join-Path $ReleasesDir "SHA256SUMS.txt"
# Only the artifacts we just built -- NOT a bare preflight-* glob, which also
# catches the "preflight-windows-amd64.exe~" backup Windows leaves when go build
# overwrites a locked/old exe (that stray entry then pollutes SHA256SUMS and the
# allowlist-by-hash guidance derived from it).
$Lines = $Targets | ForEach-Object {
    $name = "preflight-$($_.GOOS)-$($_.GOARCH)$($_.Ext)"
    $hash = (Get-FileHash -Path (Join-Path $ReleasesDir $name) -Algorithm SHA256).Hash.ToLower()
    "$hash  $name"
}

# Layer 2 entrypoint scripts get their own checksums too. Unlike the .java/
# .cs/.py sources, which only ever run under a signed dotnet/java/python
# interpreter, run.sh/run.cmd are executed directly by the OS -- exactly like
# the binary above -- so an endpoint allowlisting product can gate them the
# same way, and without a published hash a security team has nothing to
# allowlist it by.
# Paths are relative to this release folder's root, matching the shipped ZIP's
# internal layout, so they verify correctly once unzipped.
$Layer2Root = Join-Path $ScriptDir "..\layer2"
$Stacks = @("csharp", "java", "python", "typescript")
foreach ($stack in $Stacks) {
    foreach ($script in @("run.sh", "run.cmd")) {
        $path = Join-Path $Layer2Root "$stack\$script"
        $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
        $Lines += "$hash  layer2/$stack/$script"
    }
}

$Lines | Set-Content -Encoding ascii $ChecksumFile

Write-Host ""
Write-Host "Done. Artifacts + checksums in ${ReleasesDir}:"
Get-Content $ChecksumFile
Write-Host ""
Write-Host "NOTE: artifacts are UNSIGNED. Use the checksums above for an allowlist-by-hash rule."
