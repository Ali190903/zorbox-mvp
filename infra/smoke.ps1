# ZORBOX Smoke Test - Windows PowerShell
Write-Host "=== ZORBOX Smoke Test ===" -ForegroundColor Cyan
Write-Host ""

$Failed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url
    )
    
    Write-Host -NoNewline "Testing $Name... "
    
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "FAILED (Status: $($response.StatusCode))" -ForegroundColor Red
            $script:Failed++
        }
    } catch {
        Write-Host "FAILED ($_)" -ForegroundColor Red
        $script:Failed++
    }
}

# Health checks
Write-Host "--- Health Checks ---"
Test-Endpoint -Name "Orchestrator Health" -Url "http://localhost:8080/healthz"
Test-Endpoint -Name "Reporter Health" -Url "http://localhost:8090/healthz"
Test-Endpoint -Name "TI Enrichment Health" -Url "http://localhost:8070/healthz"
Test-Endpoint -Name "Static Analyzer Health" -Url "http://localhost:8060/healthz"
Test-Endpoint -Name "Sandbox Native Health" -Url "http://localhost:8050/healthz"

Write-Host ""
Write-Host "--- Metrics Endpoints ---"
Test-Endpoint -Name "Orchestrator Metrics" -Url "http://localhost:8080/metrics"
Test-Endpoint -Name "Reporter Metrics" -Url "http://localhost:8090/metrics"
Test-Endpoint -Name "TI Metrics" -Url "http://localhost:8070/metrics"
Test-Endpoint -Name "Static Analyzer Metrics" -Url "http://localhost:8060/metrics"
Test-Endpoint -Name "Sandbox Metrics" -Url "http://localhost:8050/metrics"

Write-Host ""
Write-Host "--- Monitoring Stack ---"
Test-Endpoint -Name "Prometheus" -Url "http://localhost:9090/-/healthy"
Test-Endpoint -Name "Grafana" -Url "http://localhost:3000/api/health"

Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
if ($Failed -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$Failed test(s) failed!" -ForegroundColor Red
    exit 1
}
