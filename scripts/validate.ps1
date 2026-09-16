# Path Authority 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.
#
# Full validation closure for one checkout. It configures, builds and tests the
# Release, Debug, AddressSanitizer and static-analysis configurations, runs every
# example and the benchmark suite, installs the package and validates an
# independent consumer against the installed artifacts only.
#
# No test or validation command sets a timeout: a hanging test is a defect.
param(
  [string]$Source = (Split-Path -Parent $PSScriptRoot),
  [string]$WorkRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) "..\pa-validation"),
  [switch]$SkipAnalyze,
  [switch]$SkipAsan
)

$ErrorActionPreference = "Stop"
$script:Failures = 0

function Step([string]$Name, [scriptblock]$Body) {
  Write-Output ""
  Write-Output "=== $Name ==="
  try {
    & $Body
  } catch {
    Write-Output "STEP-FAILED $Name : $_"
    $script:Failures++
  }
}

function Configure([string]$Build, [string]$Config, [string[]]$Extra) {
  $arguments = @("-S", $Source, "-B", $Build, "-G", "Visual Studio 17 2022", "-A", "x64") + $Extra
  & cmake @arguments
  if ($LASTEXITCODE -ne 0) { throw "configure failed for $Config" }
}

function Build([string]$Build, [string]$Config) {
  & cmake --build $Build --config $Config
  if ($LASTEXITCODE -ne 0) { throw "build failed for $Config" }
}

function RunTests([string]$Build, [string]$Config, [string]$PathPrefix = "") {
  if ($PathPrefix -ne "") { $env:PATH = "$PathPrefix;$env:PATH" }
  Push-Location $Build
  try {
    & ctest -C $Config --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "tests failed for $Config" }
  } finally {
    Pop-Location
  }
}

function RunExamples([string]$Build, [string]$Config) {
  $directory = Join-Path $Build "examples\$Config"
  Get-ChildItem (Join-Path $directory "ex_*.exe") | ForEach-Object {
    & $_.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "example $($_.Name) failed" }
  }
  Write-Output "examples=ok"
}

New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
$release = Join-Path $WorkRoot "release"
$debug = Join-Path $WorkRoot "debug"
$asan = Join-Path $WorkRoot "asan"
$analyze = Join-Path $WorkRoot "analyze"
$install = Join-Path $WorkRoot "install"
$consumer = Join-Path $WorkRoot "consumer"

Step "release" {
  Configure $release "Release" @("-DPATH_AUTHORITY_BUILD_TESTS=ON")
  Build $release "Release"
  RunTests $release "Release"
  RunExamples $release "Release"
}

Step "debug" {
  Configure $debug "Debug" @("-DPATH_AUTHORITY_BUILD_TESTS=ON")
  Build $debug "Debug"
  RunTests $debug "Debug"
}

Step "benchmarks" {
  & (Join-Path $release "Release\path_authority_benchmarks.exe") | Select-Object -Last 6
  if ($LASTEXITCODE -ne 0) { throw "benchmarks failed" }
}

Step "install-and-consumer" {
  Remove-Item $install -Recurse -Force -ErrorAction SilentlyContinue
  & cmake --install $release --config Release --prefix $install
  if ($LASTEXITCODE -ne 0) { throw "install failed" }
  Remove-Item $consumer -Recurse -Force -ErrorAction SilentlyContinue
  & cmake -S (Join-Path $Source "tests\consumer") -B $consumer -G "Visual Studio 17 2022" -A x64 "-DCMAKE_PREFIX_PATH=$install"
  if ($LASTEXITCODE -ne 0) { throw "consumer configure failed" }
  & cmake --build $consumer --config Release
  if ($LASTEXITCODE -ne 0) { throw "consumer build failed" }
  & (Join-Path $consumer "Release\consumer.exe")
  if ($LASTEXITCODE -ne 0) { throw "consumer run failed" }
}

if (-not $SkipAsan) {
  Step "address-sanitizer" {
    $runtime = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $runtime) { throw "the AddressSanitizer runtime is not installed" }
    Configure $asan "Release" @("-DPATH_AUTHORITY_ENABLE_ASAN=ON")
    Build $asan "Release"
    RunTests $asan "Release" $runtime.DirectoryName
  }
}

if (-not $SkipAnalyze) {
  Step "static-analysis" {
    Configure $analyze "Release" @("-DPATH_AUTHORITY_ENABLE_ANALYZE=ON",
                                  "-DPATH_AUTHORITY_BUILD_TESTS=OFF",
                                  "-DPATH_AUTHORITY_BUILD_EXAMPLES=OFF",
                                  "-DPATH_AUTHORITY_BUILD_BENCHMARKS=OFF")
    Build $analyze "Release"
  }
}

Write-Output ""
if ($script:Failures -ne 0) {
  Write-Output "validation=FAILED failures=$script:Failures"
  exit 1
}
Write-Output "validation=OK"
