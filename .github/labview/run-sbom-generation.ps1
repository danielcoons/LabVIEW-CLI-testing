<#
.SYNOPSIS
    Generates a Software Bill of Materials (SBOM) for LabVIEW projects using JKI's VIPM CLI.
    Emits an SPDX-compliant JSON file (sbom.json) and an HTML widget (sbom_widget.html)
    intended for dashboard integration.

.PARAMETER WorkspaceRoot
    Absolute path to the checked-out project repository. Default: C:\workspace.

.PARAMETER ResultsDir
    Directory where sbom.json and sbom_widget.html will be saved. Default: C:\workspace\ci-out\sbom.
#>
param(
    [string]$WorkspaceRoot = 'C:\workspace',
    [string]$ResultsDir    = 'C:\workspace\ci-out\sbom'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Ensure output directory exists
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

# -- Helper Functions ---------------------------------------------------------
function Resolve-Cmd([string[]]$names) {
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c -and $c.Source) { return $c.Source }
    }
    return $null
}

function Sync-PathFromRegistry {
    # VIPM-installed CLIs add their directory to system PATH, but Windows container
    # processes don't always inherit registry PATH updates automatically.
    try {
        $machine = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'Path' -ErrorAction SilentlyContinue).Path
        $user    = (Get-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -ErrorAction SilentlyContinue).Path
        $current = @($env:Path -split ';')
        foreach ($raw in @($machine, $user)) {
            if (-not $raw) { continue }
            foreach ($entry in ([System.Environment]::ExpandEnvironmentVariables($raw) -split ';')) {
                $e = $entry.Trim()
                if ($e -and ($current -notcontains $e)) { $env:Path = $env:Path.TrimEnd(';') + ';' + $e; $current += $e }
            }
        }
    } catch { 
        Write-Host "  (PATH refresh from registry skipped: $($_.Exception.Message))" 
    }
}

function Resolve-VIPMCLI {
    Sync-PathFromRegistry
    $cli = Resolve-Cmd @('vipm', 'vipm.exe')
    if ($cli) { return $cli }

    $standardPaths = @(
        "C:\Program Files (x86)\JKI\VI Package Manager\vipm.exe",
        "C:\Program Files\JKI\VI Package Manager\vipm.exe"
    )
    foreach ($p in $standardPaths) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

# -- Main Generation Logic ----------------------------------------------------
function Invoke-SbomGeneration([string]$Workspace, [string]$OutDir) {
    Write-Host "=== JKI VIPM SBOM Generation ==="
    Write-Host "  Workspace : $Workspace"
    Write-Host "  Results   : $OutDir"

    $VipmCli = Resolve-VIPMCLI
    Write-Host "  VIPM CLI  : $(if ($VipmCli) { $VipmCli } else { '<not found>' })"
    Write-Host ""

    $sbomPackages = @()

    if ($VipmCli -and (Test-Path $VipmCli)) {
        Write-Host "Generating native VIPM SBOM via VIPM CLI..." -ForegroundColor Cyan
        
        # 1. Locate main project file (.lvproj), explicitly ignoring tooling/CI folders
        $projFile = Get-ChildItem -Path $Workspace -Filter '*.lvproj' -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/](\.github|ci-out|build)[\\/]' } |
            Select-Object -First 1
        
        if ($projFile) {
            $projPath = $projFile.FullName
            $outPath  = Join-Path $OutDir "sbom.json"
            
            Write-Host "  Project : $projPath"
            Write-Host "  Output  : $outPath"

            # 2. Ensure VI Server (Port 3363) is enabled in LabVIEW.ini if present
            $lvIniPaths = Get-ChildItem "C:\Program Files*\National Instruments\LabVIEW*\LabVIEW.ini" -ErrorAction SilentlyContinue
            foreach ($ini in $lvIniPaths) {
                try {
                    $content = Get-Content $ini.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -and $content -notmatch "server.tcp.enabled=True") {
                        Write-Host "Enabling VI Server Port 3363 in $($ini.FullName)..."
                        Add-Content -Path $ini.FullName -Value "`r`nserver.tcp.enabled=True`r`nserver.tcp.port=3363`r`nserver.tcp.access=`"+127.0.0.1;+localhost`""
                    }
                } catch {
                    Write-Warning "Could not update $($ini.FullName): $($_.Exception.Message)"
                }
            }

            try {
                # 3. Execute VIPM SBOM command
                & $VipmCli sbom "$projPath" --format "cyclonedx" --schema-version "1.5" --output "$outPath"

                if (Test-Path $outPath) {
                    Write-Host "VIPM SBOM generated successfully!" -ForegroundColor Green
                    $sbomRaw = Get-Content $outPath | ConvertFrom-Json
                    
                    if ($sbomRaw.components) {
                        $sbomPackages = @($sbomRaw.components | ForEach-Object {
                            [pscustomobject]@{
                                Name    = $_.name
                                Version = $_.version
                                Vendor  = if ($_.publisher) { $_.publisher } else { "VIPM Package" }
                            }
                        })
                    }
                } else {
                    Write-Warning "VIPM CLI completed but output file was not created at $outPath"
                }
            } catch {
                Write-Warning "Failed to execute VIPM CLI sbom command: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "No valid user .lvproj file found in workspace root $Workspace (excluding .github)."
        }
    }

    # Structure document in SPDX 2.3 standard JSON format
    $sbomDoc = @{
        spdxVersion = "SPDX-2.3"
        dataLicense = "CC0-1.0"
        SPDXID      = "SPDXRef-DOCUMENT"
        name        = "LabVIEW-Container-Dependencies"
        packages    = $sbomPackages
        created     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    # Save JSON artifact
    $jsonPath = Join-Path $OutDir "sbom.json"
    $sbomDoc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host "Wrote SPDX JSON SBOM -> $jsonPath" -ForegroundColor Green

    # Generate HTML Widget for Dashboard Insertion
    $htmlWidget = @"
<div class="card sbom-card">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h4>Software Bill of Materials (SBOM) - JKI VIPM Dependencies</h4>
        <a href="sbom.json" download class="btn btn-sm btn-outline-primary">Download SPDX JSON</a>
    </div>
    <div class="card-body">
        <table class="table table-sm table-striped">
            <thead>
                <tr>
                    <th>Package Name</th>
                    <th>Version</th>
                    <th>Vendor</th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($pkg in $sbomPackages) {
        $htmlWidget += @"
                <tr>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($pkg.Name))</td>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($pkg.Version))</td>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($pkg.Vendor))</td>
                </tr>
"@
    }
    $htmlWidget += @"
            </tbody>
        </table>
    </div>
</div>
"@

    # Save HTML artifact
    $htmlPath = Join-Path $OutDir "sbom_widget.html"
    $htmlWidget | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    Write-Host "Wrote HTML Dashboard Widget -> $htmlPath" -ForegroundColor Green
}

# Run SBOM Generator
Invoke-SbomGeneration -Workspace $WorkspaceRoot -OutDir $ResultsDir
