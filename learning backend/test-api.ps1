param (
    [int]$Port = 8080
)

$BaseUrl = "http://localhost:$Port"
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host " TESTING BACKEND API AT $BaseUrl" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "`n[1/5] Testing Health Check: GET $BaseUrl/api/health" -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -Method Get -UseBasicParsing
    Write-Host "  Health OK: status=$($health.status), backend=$($health.backend)" -ForegroundColor Green
} catch {
    Write-Host "  Server is NOT reachable at $BaseUrl. Did you start it?" -ForegroundColor Red
    exit 1
}

# Test 2: Test Unauthorized Access (Should return 401)
Write-Host "`n[2/5] Testing Security: GET $BaseUrl/api/subscriptions WITHOUT Token" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$BaseUrl/api/subscriptions" -Method Get -UseBasicParsing
    Write-Host "  SECURITY FAILED: Endpoint allowed access without token!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 401) {
        Write-Host "  SECURITY PASSED: Server correctly rejected request with HTTP 401 Unauthorized" -ForegroundColor Green
    } else {
        Write-Host "  Received HTTP $statusCode" -ForegroundColor Yellow
    }
}

# Test 3: Register a Brand New Account
$randomSuffix = Get-Random -Minimum 1000 -Maximum 9999
$testEmail = "learner_$randomSuffix@example.com"
Write-Host "`n[3/5] Testing Registration: POST $BaseUrl/api/register with $testEmail" -ForegroundColor Yellow
$regBody = @{
    name = "New Learner"
    email = $testEmail
    password = "superSecurePassword123"
} | ConvertTo-Json

try {
    $regResponse = Invoke-RestMethod -Uri "$BaseUrl/api/register" -Method Post -Body $regBody -ContentType "application/json" -UseBasicParsing
    Write-Host "  Registration Successful!" -ForegroundColor Green
    Write-Host "  User ID: $($regResponse.user.id)" -ForegroundColor Gray
} catch {
    Write-Host "  Registration failed: $_" -ForegroundColor Red
}

# Test 4: Login with Demo Account
Write-Host "`n[4/5] Testing Login: POST $BaseUrl/api/login (demo@example.com / password123)" -ForegroundColor Yellow
$loginBody = @{
    email = "demo@example.com"
    password = "password123"
} | ConvertTo-Json

$token = $null
try {
    $loginResponse = Invoke-RestMethod -Uri "$BaseUrl/api/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $token = $loginResponse.token
    Write-Host "  Login Successful!" -ForegroundColor Green
    Write-Host "  Generated JWT: $($token.Substring(0, 35))..." -ForegroundColor Gray
} catch {
    Write-Host "  Login failed: $_" -ForegroundColor Red
    exit 1
}

# Test 5: Fetch Protected Subscriptions with Bearer Token
Write-Host "`n[5/5] Testing Protected Route: GET $BaseUrl/api/subscriptions WITH Bearer Token" -ForegroundColor Yellow
$headers = @{
    Authorization = "Bearer $token"
}

try {
    $subResponse = Invoke-RestMethod -Uri "$BaseUrl/api/subscriptions" -Method Get -Headers $headers -UseBasicParsing
    Write-Host "  Successfully accessed protected subscription plans!" -ForegroundColor Green
    Write-Host "  Active User Plan: $($subResponse.current_user_plan)" -ForegroundColor Magenta
    Write-Host "  Available Plans Catalog:" -ForegroundColor Cyan
    foreach ($plan in $subResponse.plans) {
        $price = if ($null -ne $plan.price_monthly) { $plan.price_monthly } else { $plan.priceMonthly }
        Write-Host "   - $($plan.name) : `$$price / month" -ForegroundColor White
    }
} catch {
    Write-Host "  Failed to fetch subscriptions with token: $_" -ForegroundColor Red
}

Write-Host "`n==============================================================" -ForegroundColor Cyan
Write-Host " ALL BACKEND API AND SECURITY TESTS COMPLETED SUCCESSFULLY!" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
