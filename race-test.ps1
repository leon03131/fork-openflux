$ErrorActionPreference = "Stop"

$Server = "gotest@2.27.203.15"
$Key = "$env:USERPROFILE\.ssh\go_race_runner"

if (-not (Test-Path ".\go.mod")) {
    Write-Error "go.mod не найден. Запускай скрипт из корня Go-проекта."
    exit 2
}

$Id = [Guid]::NewGuid().ToString("N")
$Archive = Join-Path $env:TEMP "go-race-$Id.tgz"
$RemoteArchive = "/srv/go-race/incoming/upload.$Id.tgz"

try {
    Write-Host "==> Packing project..."

    & tar.exe `
        --exclude=.git `
        --exclude=.idea `
        --exclude=.vscode `
        --exclude=.vs `
        -czf $Archive .

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $Size = [math]::Round((Get-Item $Archive).Length / 1MB, 2)
    Write-Host "==> Archive: $Size MB"
    Write-Host "==> Uploading to 2.27.203.15..."

    & scp.exe `
        -i $Key `
        -o IdentitiesOnly=yes `
        -o BatchMode=yes `
        $Archive `
        "${Server}:$RemoteArchive"

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Host ""
    Write-Host "==> Running go test -race..."
    Write-Host ""

    & ssh.exe `
        -i $Key `
        -o IdentitiesOnly=yes `
        -o BatchMode=yes `
        $Server `
        "sudo -n /usr/local/sbin/go-race-runner $RemoteArchive"

    $Code = $LASTEXITCODE

    Write-Host ""

    if ($Code -eq 0) {
        Write-Host "==> RACE TEST PASSED"
    }
    else {
        Write-Host "==> RACE TEST FAILED (exit code $Code)"
    }

    exit $Code
}
finally {
    if (Test-Path $Archive) {
        Remove-Item -Force $Archive
    }
}