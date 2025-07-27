<#
.SYNOPSIS
    Generates an interactive HTML report of Microsoft Entra ID Service Principals (Enterprise Applications) with risk assessment and cleanup recommendations.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves service principals matching the Enterprise Applications filter, analyzes permissions, sign-in activity, and credentials.
    It calculates a risk score based on configurable rules, flags cleanup candidates, and produces an optimized, filterable HTML report.
    Supports pre-filtering for performance when querying sign-in logs.

.AUTHOR
    Matej Klemencic (www.matej.guru)

.NOTES
    Version:        1.0
    Last Modified:  2025-07-27

.PARAMETER OutputPath
    Path to save the generated HTML report. Defaults to "EntraIDServicePrincipalReport.html".

.PARAMETER OnlyWithPermissions
    Include only service principals that have at least one permission (delegated, application or directory role).

.PARAMETER MinimumPermissions
    Include only service principals with total permissions count >= this number. Default is 0 (no minimum).

.PARAMETER InactiveThresholdDays
    Threshold (in days) to count an application as inactive for summary statistics. Default is 30 days.

.PARAMETER IncludeSignInLogs
    Switch to include sign-in log analysis (last 30 days). Adds AuditLog.Read.All scope and enables log queries.

.PARAMETER RiskConfigPath
    Path to a JSON file with custom risk scoring configuration. If provided and valid, overrides default risk rules.

.PARAMETER OnlyWithAppRegistrations
    Include only applications that have corresponding App Registration objects in the tenant.

.PARAMETER OnlyServicePrincipalsOnly
    Include only service principals without an App Registration (e.g., gallery or legacy apps).

.EXAMPLE
    # Generate default report
    .\Get-EntraIDServicePrincipalReport.ps1

.EXAMPLE
    # Include sign-in logs and filter only apps with registrations
    .\Get-EntraIDServicePrincipalReport.ps1 -IncludeSignInLogs -OnlyWithAppRegistrations

.EXAMPLE
    # List only SPs with at least 5 permissions
    .\Get-EntraIDServicePrincipalReport.ps1 -MinimumPermissions 5

.INSTALLATION
    Install the required Microsoft Graph modules:

    # Install only necessary modules
    Install-Module \
      -Name Microsoft.Graph.Authentication,Microsoft.Graph.Applications,Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.DirectoryManagement,Microsoft.Graph.Reports \
      -Scope CurrentUser \
      -AllowClobber

    # Or install the full umbrella module
    Install-Module \
      -Name Microsoft.Graph \
      -Scope CurrentUser \
      -AllowClobber
#>
param(
    [string]$OutputPath = "EntraIDServicePrincipalReport.html",
    [switch]$OnlyWithPermissions,
    [int]$MinimumPermissions = 0,
    [int]$InactiveThresholdDays = 30,
    [switch]$IncludeSignInLogs,
    [string]$RiskConfigPath = $null,
    [switch]$OnlyWithAppRegistrations,
    [switch]$OnlyServicePrincipalsOnly
)

# Risk scoring configuration
$riskConfig = @{
    HighRiskPermissions = @(
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All',
        'Group.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
        'Policy.ReadWrite.All', 'Sites.FullControl.All', 'Files.ReadWrite.All',
        'Mail.ReadWrite', 'Calendars.ReadWrite', 'Contacts.ReadWrite',
        'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementApps.ReadWrite.All'
    )
    MediumRiskPermissions = @(
        'Directory.Read.All', 'User.Read.All', 'Group.Read.All',
        'Application.Read.All', 'Sites.Read.All', 'Files.Read.All',
        'Mail.Read', 'Calendars.Read', 'Contacts.Read'
    )
    HighRiskDirectoryRoles = @(
        'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
        'Application Administrator', 'Cloud Application Administrator', 'User Administrator',
        'Exchange Administrator', 'SharePoint Administrator', 'Conditional Access Administrator'
    )
    SuspiciousKeywords = @(
        'test', 'demo', 'temp', 'old', 'backup', 'legacy', 'dev', 'staging'
    )
}

# Load external risk configuration if provided
if ($RiskConfigPath -and (Test-Path $RiskConfigPath)) {
    try {
        $externalConfig = Get-Content $RiskConfigPath | ConvertFrom-Json
        $riskConfig = $externalConfig
        Write-Host "Loaded external risk configuration from $RiskConfigPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to load external risk configuration. Using default settings."
    }
}

# Function to safely import modules
function Import-GraphModuleSafely {
    param([string]$ModuleName)
    
    try {
        Import-Module $ModuleName -Force -ErrorAction Stop
        Write-Host "Successfully imported $ModuleName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not import $ModuleName. Attempting to use Microsoft.Graph umbrella module..."
        try {
            Import-Module Microsoft.Graph -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import required Graph modules. Please ensure Microsoft Graph PowerShell is properly installed."
            Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
}

# Function to calculate risk score
function Get-RiskScore {
    param(
        [array]$Permissions,
        [array]$DirectoryRoles,
        [string]$DisplayName,
        [int]$DaysSinceLastSignIn,
        [string]$PublisherName,
        [bool]$HasCredentials,
        [bool]$HasAppRegistration,
        $TotalUsers
    )
    
    $score = 0
    $riskFactors = @()
    
    # Permission-based scoring
    foreach ($perm in $Permissions) {
        if ($perm.Permission -in $riskConfig.HighRiskPermissions) {
            $score += 10
            $riskFactors += "High-risk permission: $($perm.Permission)"
        }
        elseif ($perm.Permission -in $riskConfig.MediumRiskPermissions) {
            $score += 5
            $riskFactors += "Medium-risk permission: $($perm.Permission)"
        }
        
        # Application permissions are higher risk than delegated
        if ($perm.Type -eq "Application") {
            $score += 3
        }
    }
    
    # Directory role scoring
    foreach ($role in $DirectoryRoles) {
        if ($role.Permission -in $riskConfig.HighRiskDirectoryRoles) {
            $score += 15
            $riskFactors += "High-risk directory role: $($role.Permission)"
        }
        else {
            $score += 8
            $riskFactors += "Directory role: $($role.Permission)"
        }
    }
    
    # Inactivity scoring
    if ($DaysSinceLastSignIn -gt 30) {
        $score += 8
        $riskFactors += "No activity for over 30 days"
    }
    
    # Suspicious naming
    $suspiciousName = $riskConfig.SuspiciousKeywords | Where-Object { $DisplayName -match $_ }
    if ($suspiciousName) {
        $score += 5
        $riskFactors += "Suspicious name contains: $($suspiciousName -join ', ')"
    }
    
    # Unknown publisher
    if ([string]::IsNullOrEmpty($PublisherName) -or $PublisherName -eq "Unknown") {
        $score += 3
        $riskFactors += "Unknown or missing publisher"
    }
    
    # High user count with sensitive permissions
    if ($TotalUsers -eq "All Users" -and $score -gt 10) {
        $score += 5
        $riskFactors += "High permissions with all users access"
    }
    elseif ($TotalUsers -is [int] -and $TotalUsers -gt 50 -and $score -gt 5) {
        $score += 3
        $riskFactors += "High permissions affecting many users ($TotalUsers users)"
    }
    
    # No active credentials (potentially orphaned) - only applies to apps with registrations
    if (-not $HasCredentials -and $HasAppRegistration) {
        $score += 4
        $riskFactors += "No active credentials/certificates"
    }
    
    # Service Principal without App Registration (could be suspicious)
    if (-not $HasAppRegistration) {
        $score += 2
        $riskFactors += "Service Principal without App Registration"
    }
    
    return @{
        Score = $score
        Level = if ($score -ge 25) { "Critical" } elseif ($score -ge 15) { "High" } elseif ($score -ge 8) { "Medium" } else { "Low" }
        Factors = $riskFactors
    }
}

# Function to get comprehensive sign-in activity
function Get-SignInActivity {
    param([string]$AppId, [string]$ServicePrincipalId)
    
    if (-not $IncludeSignInLogs) {
        return @{
            LastSignIn = $null
            DaysSinceLastSignIn = -1
            SignInCount30Days = -1
            UniqueUsers30Days = -1
            SignInTypes = "N/A - Sign-in logs not requested"
            SignInStatus = "Not checked"
        }
    }
    
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $allSignInLogs = @()
        $signInTypes = @()
        
        # Check interactive sign-ins
        try {
            $interactiveSignIns = Get-MgAuditLogSignIn -Filter "appId eq '$AppId' and createdDateTime ge $thirtyDaysAgo" -All -ErrorAction SilentlyContinue
            if ($interactiveSignIns) {
                $allSignInLogs += $interactiveSignIns
                $signInTypes += "Interactive"
            }
        }
        catch { Write-Verbose "Could not retrieve interactive sign-ins for $AppId" }
        
        # Check service principal sign-ins
        try {
            $servicePrincipalSignIns = Get-MgAuditLogSignIn -Filter "servicePrincipalId eq '$ServicePrincipalId' and createdDateTime ge $thirtyDaysAgo" -All -ErrorAction SilentlyContinue
            if ($servicePrincipalSignIns) {
                $allSignInLogs += $servicePrincipalSignIns
                $signInTypes += "Service Principal"
            }
        }
        catch { Write-Verbose "Could not retrieve service principal sign-ins for $ServicePrincipalId" }
        
        # Check as resource
        try {
            $resourceSignIns = Get-MgAuditLogSignIn -Filter "resourceId eq '$ServicePrincipalId' and createdDateTime ge $thirtyDaysAgo" -All -ErrorAction SilentlyContinue
            if ($resourceSignIns) {
                $allSignInLogs += $resourceSignIns
                $signInTypes += "As Resource"
            }
        }
        catch { Write-Verbose "Could not retrieve resource sign-ins for $ServicePrincipalId" }
        
        # Remove duplicates and process results
        $uniqueSignInLogs = $allSignInLogs | Sort-Object Id -Unique
        
        if ($uniqueSignInLogs -and $uniqueSignInLogs.Count -gt 0) {
            $lastSignIn = ($uniqueSignInLogs | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
            $daysSinceLastSignIn = if ($lastSignIn) { (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days } else { 9999 }
            $uniqueUsers = ($uniqueSignInLogs | Where-Object { $_.UserId } | Select-Object UserId -Unique).Count
            
            return @{
                LastSignIn = $lastSignIn
                DaysSinceLastSignIn = $daysSinceLastSignIn
                SignInCount30Days = $uniqueSignInLogs.Count
                UniqueUsers30Days = $uniqueUsers
                SignInTypes = $signInTypes -join ", "
                SignInStatus = "Sign-ins found"
            }
        }
        else {
            return @{
                LastSignIn = $null
                DaysSinceLastSignIn = 9999
                SignInCount30Days = 0
                UniqueUsers30Days = 0
                SignInTypes = "No sign-ins found"
                SignInStatus = "No sign-ins found"
            }
        }
    }
    catch {
        return @{
            LastSignIn = $null
            DaysSinceLastSignIn = 9999
            SignInCount30Days = 0
            UniqueUsers30Days = 0
            SignInTypes = "Error retrieving logs"
            SignInStatus = "No sign-ins found"
        }
    }
}

# Function to get application credentials and registration info
function Get-ApplicationCredentials {
    param([string]$AppId)
    
    try {
        $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
        if ($app) {
            $activeSecrets = $app.PasswordCredentials | Where-Object { $_.EndDateTime -gt (Get-Date) }
            $activeCerts = $app.KeyCredentials | Where-Object { $_.EndDateTime -gt (Get-Date) }
            
            return @{
                HasAppRegistration = $true
                AppRegistrationId = $app.Id
                HasActiveCredentials = ($activeSecrets.Count -gt 0 -or $activeCerts.Count -gt 0)
                ActiveSecrets = $activeSecrets.Count
                ActiveCertificates = $activeCerts.Count
                ExpiringCredentials = ($app.PasswordCredentials + $app.KeyCredentials | Where-Object { 
                    $_.EndDateTime -gt (Get-Date) -and $_.EndDateTime -lt (Get-Date).AddDays(30) 
                }).Count
                AppType = if ($app.Web.RedirectUris.Count -gt 0 -or $app.Spa.RedirectUris.Count -gt 0) { "Web/SPA App" } 
                         elseif ($app.PublicClient.RedirectUris.Count -gt 0) { "Mobile/Desktop App" } 
                         elseif ($app.RequiredResourceAccess.Count -gt 0) { "Daemon/Service App" } 
                         else { "Unknown App Type" }
            }
        }
        else {
            return @{
                HasAppRegistration = $false
                AppRegistrationId = $null
                HasActiveCredentials = $false
                ActiveSecrets = 0
                ActiveCertificates = 0
                ExpiringCredentials = 0
                AppType = "Service Principal Only"
            }
        }
    }
    catch {
        return @{
            HasAppRegistration = $false
            AppRegistrationId = $null
            HasActiveCredentials = $false
            ActiveSecrets = 0
            ActiveCertificates = 0
            ExpiringCredentials = 0
            AppType = "Unknown"
        }
    }
}

# Function to get and process permissions for filtering
function Get-ServicePrincipalPermissions {
    param($ServicePrincipal)
    
    # Get delegated permissions
    $delegatedGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($ServicePrincipal.Id)'" -All
    
    # Get application permissions
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -All
    
    # Get directory role assignments
    $roleAssignments = @()
    try {
        $allRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($ServicePrincipal.Id)'" -All -ErrorAction SilentlyContinue
        foreach ($assignment in $allRoleAssignments) {
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
            if ($roleDefinition) {
                $roleAssignments += $roleDefinition
            }
        }
    }
    catch {
        # Fallback method
        try {
            $allDirectoryRoles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
            foreach ($role in $allDirectoryRoles) {
                try {
                    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
                    if ($roleMembers | Where-Object { $_.Id -eq $ServicePrincipal.Id }) {
                        $roleAssignments += $role
                    }
                }
                catch { continue }
            }
        }
        catch { Write-Warning "Could not retrieve directory role assignments for $($ServicePrincipal.DisplayName)" }
    }
    
    # Calculate total permission count for filtering
    $delegatedPermissionCount = 0
    foreach ($grant in $delegatedGrants) {
        if ($grant.Scope) {
            $scopes = $grant.Scope.Split(' ') | Where-Object { $_ -ne '' }
            $delegatedPermissionCount += $scopes.Count
        }
    }
    
    $applicationPermissionCount = $appRoleAssignments.Count
    $directoryRoleCount = $roleAssignments.Count
    $totalPermissions = $delegatedPermissionCount + $applicationPermissionCount + $directoryRoleCount
    
    return @{
        TotalPermissions = $totalPermissions
        DelegatedGrants = $delegatedGrants
        AppRoleAssignments = $appRoleAssignments
        RoleAssignments = $roleAssignments
        ApplicationPermissionCount = $applicationPermissionCount
        DelegatedPermissionCount = $delegatedPermissionCount
        DirectoryRoleCount = $directoryRoleCount
    }
}

# Import required modules
Write-Host "Importing Microsoft Graph modules..." -ForegroundColor Green
Import-GraphModuleSafely "Microsoft.Graph.Applications"
Import-GraphModuleSafely "Microsoft.Graph.Identity.SignIns"
Import-GraphModuleSafely "Microsoft.Graph.Identity.DirectoryManagement"

if ($IncludeSignInLogs) {
    Import-GraphModuleSafely "Microsoft.Graph.Reports"
}

# Connect to Microsoft Graph
$scopes = @(
    "Application.Read.All",
    "Directory.Read.All", 
    "DelegatedPermissionGrant.Read.All",
    "RoleManagement.Read.Directory"
)

if ($IncludeSignInLogs) {
    $scopes += "AuditLog.Read.All"
}

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
Connect-MgGraph -Scopes $scopes

Write-Host "Gathering Enterprise Applications..." -ForegroundColor Green

# Get service principals that match the Entra ID portal "Enterprise Applications" filter
$servicePrincipals = Get-MgServicePrincipal -All -Property @(
    "Id", "AppId", "DisplayName", "AppOwnerOrganizationId", 
    "ServicePrincipalType", "AppRoles", "Oauth2PermissionScopes", "SignInAudience", 
    "PublisherName", "Tags", "AppDisplayName", "CreatedDateTime"
) | Where-Object { 
    $_.ServicePrincipalType -eq "Application" -and
    $_.AppOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -and
    #$_.AppOwnerOrganizationId -ne $null -and
    $_.AppId -notin @(
        "00000003-0000-0000-c000-000000000000", # Microsoft Graph
        "00000002-0000-0ff1-ce00-000000000000", # Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000", # Office 365 SharePoint Online
        "c5393580-f805-4401-95e8-94b7a6ef2fc2", # Office 365 Management APIs
        "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
        "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3", # Microsoft Graph PowerShell
        "1b730954-1685-4b74-9bfd-dac224a7b894", # Azure Active Directory PowerShell
        "1950a258-227b-4e31-a9cf-717495945fc2", # Microsoft Azure PowerShell
        "797f4846-ba00-4fd7-ba43-dac1f8f63013"  # Windows Azure Service Management API
    ) -and
    ($_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp" -or
     $_.AppOwnerOrganizationId -eq (Get-MgContext).TenantId -or
     $_.SignInAudience -in @("AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"))
}

Write-Host "Found $($servicePrincipals.Count) Enterprise Applications" -ForegroundColor Green

# PRE-FILTERING PHASE: Apply quick filters first if sign-in logs are requested
if ($IncludeSignInLogs -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly)) {
    Write-Host "`nPre-filtering applications for performance optimization..." -ForegroundColor Cyan
    
    $filteredServicePrincipals = @()
    $filteringProgress = 0
    
    foreach ($sp in $servicePrincipals) {
        $filteringProgress++
        if ($filteringProgress % 10 -eq 0) {
            Write-Progress -Activity "Pre-filtering applications" -Status "Processing $($sp.DisplayName)" -PercentComplete (($filteringProgress / $servicePrincipals.Count) * 100)
        }
        
        $shouldInclude = $true
        
        # Check App Registration filter first (fastest check)
        if ($OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly) {
            $credentials = Get-ApplicationCredentials -AppId $sp.AppId
            
            if ($OnlyWithAppRegistrations -and -not $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
            elseif ($OnlyServicePrincipalsOnly -and $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
        }
        
        # Check permissions filter (more expensive check)
        if ($shouldInclude -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0)) {
            $permissionInfo = Get-ServicePrincipalPermissions -ServicePrincipal $sp
            
            if ($OnlyWithPermissions -and $permissionInfo.TotalPermissions -eq 0) {
                $shouldInclude = $false
            }
            elseif ($MinimumPermissions -gt 0 -and $permissionInfo.TotalPermissions -lt $MinimumPermissions) {
                $shouldInclude = $false
            }
        }
        
        if ($shouldInclude) {
            $filteredServicePrincipals += $sp
        }
    }
    
    Write-Progress -Activity "Pre-filtering applications" -Completed
    Write-Host "Pre-filtering complete: $($filteredServicePrincipals.Count) applications match criteria" -ForegroundColor Green
    Write-Host "Performance gain: Skipping sign-in log queries for $($servicePrincipals.Count - $filteredServicePrincipals.Count) applications" -ForegroundColor Yellow
    
    $servicePrincipals = $filteredServicePrincipals
}

# Confirmation prompt
Write-Host "`n" -NoNewline
$confirmation = Read-Host "Continue with detailed analysis of $($servicePrincipals.Count) applications? (Y/N)"

if ($confirmation -notmatch '^[Yy]') {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 0
}

Write-Host "`nProceeding with enhanced analysis..." -ForegroundColor Green

$enhancedReport = @()
$processedCount = 0

foreach ($sp in $servicePrincipals) {
    $processedCount++
    Write-Progress -Activity "Processing applications" -Status "Processing $($sp.DisplayName)" -PercentComplete (($processedCount / $servicePrincipals.Count) * 100)
    Write-Host "Processing: $($sp.DisplayName) ($processedCount/$($servicePrincipals.Count))" -ForegroundColor Yellow
    
    # Get permissions (reuse from pre-filtering if available, otherwise get fresh)
    $permissionInfo = Get-ServicePrincipalPermissions -ServicePrincipal $sp
    
    # Process permissions into detailed format
    $permissions = @()
    $adminConsentCount = 0
    $userConsentCount = 0
    $totalUsers = 0
    
    # Process delegated permissions
    foreach ($grant in $permissionInfo.DelegatedGrants) {
        $consentType = if ($grant.ConsentType -eq "AllPrincipals") { "Admin Consent" } else { "User Consent" }
        
        if ($grant.ConsentType -eq "AllPrincipals") {
            $adminConsentCount++
            $userCount = "All Users"
        } else {
            $userConsentCount++
            $userCount = if ($grant.PrincipalId) { 1 } else { 0 }
            $totalUsers += $userCount
        }
        
        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue
        $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown" }
        
        if ($grant.Scope) {
            $scopes = $grant.Scope.Split(' ') | Where-Object { $_ -ne '' }
            foreach ($scope in $scopes) {
                $permissions += [PSCustomObject]@{
                    Type = "Delegated"
                    Permission = $scope
                    Resource = $resourceName
                    ConsentType = $consentType
                    UserCount = $userCount
                }
            }
        }
    }
    
    # Process application permissions
    foreach ($assignment in $permissionInfo.AppRoleAssignments) {
        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
        $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown" }
        
        $appRole = $resourceSP.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
        $permissionName = if ($appRole) { $appRole.Value } else { "Unknown Permission" }
        
        $permissions += [PSCustomObject]@{
            Type = "Application"
            Permission = $permissionName
            Resource = $resourceName
            ConsentType = "Admin Consent"
            UserCount = "N/A"
        }
        $adminConsentCount++
    }
    
    # Process directory role assignments
    foreach ($role in $permissionInfo.RoleAssignments) {
        $permissions += [PSCustomObject]@{
            Type = "Directory Role"
            Permission = $role.DisplayName
            Resource = "Entra ID Directory"
            ConsentType = "Admin Assignment"
            UserCount = "N/A"
        }
    }
    
    # Get sign-in activity (this is now optimized to only run on filtered apps)
    $signInActivity = Get-SignInActivity -AppId $sp.AppId -ServicePrincipalId $sp.Id
    
    # Get application credentials
    $credentials = Get-ApplicationCredentials -AppId $sp.AppId
    
    # Calculate total users affected
    $totalUsersAffected = if ($permissionInfo.DelegatedGrants | Where-Object { $_.ConsentType -eq "AllPrincipals" }) { 
        "All Users" 
    } else { 
        $totalUsers
    }
    
    # Calculate risk score
    $riskAssessment = Get-RiskScore -Permissions $permissions -DirectoryRoles ($permissionInfo.RoleAssignments | ForEach-Object { @{Permission = $_.DisplayName} }) -DisplayName $sp.DisplayName -DaysSinceLastSignIn $signInActivity.DaysSinceLastSignIn -PublisherName $sp.PublisherName -HasCredentials $credentials.HasActiveCredentials -HasAppRegistration $credentials.HasAppRegistration -TotalUsers $totalUsersAffected
    
    # Determine cleanup recommendation
    $cleanupRecommendation = "Keep"
    $cleanupReason = @()
    
    if ($riskAssessment.Level -eq "Critical") {
        $cleanupRecommendation = "Immediate Review Required"
        $cleanupReason += "Critical risk level"
    }
    elseif ($signInActivity.DaysSinceLastSignIn -gt 365 -and $permissions.Count -gt 0) {
        $cleanupRecommendation = "Consider Removal"
        $cleanupReason += "No activity for over 1 year"
    }
    elseif ($signInActivity.DaysSinceLastSignIn -gt 180 -and $riskAssessment.Score -gt 10) {
        $cleanupRecommendation = "Review Required"
        $cleanupReason += "Inactive with elevated permissions"
    }
    elseif (-not $credentials.HasActiveCredentials -and $credentials.HasAppRegistration -and $permissions.Count -gt 0) {
        $cleanupRecommendation = "Consider Removal"
        $cleanupReason += "No active credentials but has permissions"
    }
    elseif (-not $credentials.HasAppRegistration -and $permissions.Count -gt 5) {
        $cleanupRecommendation = "Review Required" 
        $cleanupReason += "Service Principal without App Registration has many permissions"
    }
    
    $enhancedReport += [PSCustomObject]@{
        DisplayName = $sp.DisplayName
        AppId = $sp.AppId
        ServicePrincipalId = $sp.Id
        PublisherName = $sp.PublisherName
        CreatedDate = $sp.CreatedDateTime
        
        # App Registration info
        HasAppRegistration = $credentials.HasAppRegistration
        AppRegistrationId = $credentials.AppRegistrationId
        AppType = $credentials.AppType
        
        # Permissions
        TotalPermissions = $permissions.Count
        ApplicationPermissions = $permissionInfo.ApplicationPermissionCount
        DelegatedPermissions = $permissionInfo.DelegatedPermissionCount
        DirectoryRoles = $permissionInfo.DirectoryRoleCount
        AdminConsentPermissions = $adminConsentCount
        UserConsentPermissions = $userConsentCount
        Permissions = $permissions
        
        # Activity metrics
        LastSignIn = $signInActivity.LastSignIn
        DaysSinceLastSignIn = $signInActivity.DaysSinceLastSignIn
        SignInCount30Days = $signInActivity.SignInCount30Days
        UniqueUsers30Days = $signInActivity.UniqueUsers30Days
        SignInTypes = $signInActivity.SignInTypes
        SignInStatus = $signInActivity.SignInStatus
        
        # Credentials
        HasActiveCredentials = $credentials.HasActiveCredentials
        ActiveSecrets = $credentials.ActiveSecrets
        ActiveCertificates = $credentials.ActiveCertificates
        ExpiringCredentials = $credentials.ExpiringCredentials
        
        # Risk assessment
        RiskScore = $riskAssessment.Score
        RiskLevel = $riskAssessment.Level
        RiskFactors = $riskAssessment.Factors
        
        # Cleanup recommendation
        CleanupRecommendation = $cleanupRecommendation
        CleanupReason = $cleanupReason -join "; "
        
        # Other fields
        TotalUsers = $totalUsersAffected
        ServicePrincipalType = $sp.ServicePrincipalType
        SignInAudience = $sp.SignInAudience
    }
}

Write-Progress -Activity "Processing applications" -Completed

# Apply remaining filters (if not already applied during pre-filtering)
if (-not $IncludeSignInLogs) {
    Write-Host "Applying final filters..." -ForegroundColor Green
    
    if ($OnlyWithPermissions) {
        $enhancedReport = $enhancedReport | Where-Object { $_.TotalPermissions -gt 0 }
    }

    if ($OnlyWithAppRegistrations) {
        $enhancedReport = $enhancedReport | Where-Object { $_.HasAppRegistration -eq $true }
    }

    if ($OnlyServicePrincipalsOnly) {
        $enhancedReport = $enhancedReport | Where-Object { $_.HasAppRegistration -eq $false }
    }

    if ($MinimumPermissions -gt 0) {
        $enhancedReport = $enhancedReport | Where-Object { $_.TotalPermissions -ge $MinimumPermissions }
    }
}

Write-Host "Final report contains $($enhancedReport.Count) applications" -ForegroundColor Green

# Calculate summary statistics
$totalApps = $enhancedReport.Count
$appsWithRegistrations = ($enhancedReport | Where-Object { $_.HasAppRegistration -eq $true }).Count
$servicePrincipalsOnly = ($enhancedReport | Where-Object { $_.HasAppRegistration -eq $false }).Count
$criticalRiskApps = ($enhancedReport | Where-Object { $_.RiskLevel -eq "Critical" }).Count
$highRiskApps = ($enhancedReport | Where-Object { $_.RiskLevel -eq "High" }).Count
$inactiveApps = ($enhancedReport | Where-Object { $_.DaysSinceLastSignIn -gt $InactiveThresholdDays }).Count
$cleanupCandidates = ($enhancedReport | Where-Object { $_.CleanupRecommendation -in @("Consider Removal", "Immediate Review Required") }).Count
$appsWithApplicationPerms = ($enhancedReport | Where-Object { $_.ApplicationPermissions -gt 0 }).Count
$appsWithDelegatedPerms = ($enhancedReport | Where-Object { $_.DelegatedPermissions -gt 0 }).Count
$totalApplicationPerms = ($enhancedReport | Measure-Object -Property ApplicationPermissions -Sum).Sum
$totalDelegatedPerms = ($enhancedReport | Measure-Object -Property DelegatedPermissions -Sum).Sum

# Get tenant information
$tenantInfo = Get-MgOrganization | Select-Object -First 1
$tenantName = $tenantInfo.DisplayName
$tenantId = $tenantInfo.Id

# Generate HTML report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Entra ID Service Principals (Enterprise apps) Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background-color: #f8f9fa; }
        .header { background-color: #00abeb; color: #ffffff; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .performance-note { background-color: #e8f5e8; border: 1px solid #4caf50; color: #2e7d2e; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-left: 4px solid #00abeb; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; font-size: 18px; }
        .summary-card .number { font-size: 32px; font-weight: bold; color: #00abeb; margin: 10px 0; }
        .summary-card .subtitle { color: #666; font-size: 14px; }
        .controls { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .controls input, .controls select { margin: 5px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .controls button { background: #00abeb; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; transition: background 0.3s; }
        .controls button:hover { background: #0088cc; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 10px; overflow: hidden; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f7fafc; font-weight: 600; cursor: pointer; user-select: none; }
        th:hover { background: #edf2f7; }
        tr:hover { background: #f7fafc; }
        .risk-critical { background: #fed7d7 !important; color: #c53030; font-weight: bold; }
        .risk-high { background: #feebc8 !important; color: #dd6b20; font-weight: bold; }
        .risk-medium { background: #fefcbf !important; color: #d69e2e; }
        .risk-low { background: #c6f6d5 !important; color: #38a169; }
        .has-app-reg { color: #38a169; font-weight: bold; }
        .sp-only { color: #e53e3e; font-weight: bold; }
        .cleanup-immediate { background: #fed7d7; color: #c53030; font-weight: bold; padding: 4px 8px; border-radius: 4px; }
        .cleanup-consider { background: #feebc8; color: #dd6b20; font-weight: bold; padding: 4px 8px; border-radius: 4px; }
        .cleanup-review { background: #fefcbf; color: #d69e2e; padding: 4px 8px; border-radius: 4px; }
        .cleanup-keep { background: #c6f6d5; color: #38a169; padding: 4px 8px; border-radius: 4px; }
        .permission-list { max-height: 200px; overflow-y: auto; font-size: 11px; }
        .permission-item { margin: 2px 0; padding: 2px 5px; background: #e2e8f0; border-radius: 3px; display: inline-block; margin-right: 5px; }
        .app-permission { background: #fed7d7; color: #c53030; font-weight: bold; }
        .delegated-permission { background: #c6f6d5; color: #38a169; }
        .directory-role { background: #feebc8; border-left: 3px solid #dd6b20; color: #dd6b20; font-weight: bold; }
        .signin-found { color: #38a169; font-weight: bold; }
        .signin-notfound { color: #e53e3e; font-weight: bold; }
        .signin-notchecked { color: #d69e2e; font-weight: bold; }
        .footer { margin-top: 30px; padding: 20px; text-align: center; color: #718096; background: white; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Entra ID Service Principals (Enterprise apps) Report</h1>
        <p><strong>Tenant:</strong> $tenantName</p>
        <p><strong>Tenant ID:</strong> $tenantId</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
"@

# Add performance optimization note if pre-filtering was used
if ($IncludeSignInLogs -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly)) {
    $html += @"
    <div class="performance-note">
        <h3>🚀 Performance Optimization Applied</h3>
        <p>Pre-filtering was used to optimize sign-in log queries. Applications were filtered first, then sign-in logs were only retrieved for matching applications, significantly improving performance.</p>
    </div>
"@
}

$html += @"
    <div class="summary">
        <div class="summary-card">
            <h3>📱 Total Applications</h3>
            <div class="number">$totalApps</div>
            <div class="subtitle">Enterprise Applications analyzed</div>
        </div>
        <div class="summary-card">
            <h3>📋 With App Registrations</h3>
            <div class="number">$appsWithRegistrations</div>
            <div class="subtitle">Apps that have corresponding App Registrations</div>
        </div>
        <div class="summary-card">
            <h3>⚙️ Service Principals Only</h3>
            <div class="number">$servicePrincipalsOnly</div>
            <div class="subtitle">Service Principals without App Registrations</div>
        </div>
        <div class="summary-card">
            <h3>🚨 Critical Risk</h3>
            <div class="number">$criticalRiskApps</div>
            <div class="subtitle">Applications requiring immediate attention</div>
        </div>
        <div class="summary-card">
            <h3>⚠️ High Risk</h3>
            <div class="number">$highRiskApps</div>
            <div class="subtitle">Applications with elevated risk scores</div>
        </div>
        <div class="summary-card">
            <h3>😴 Inactive Apps</h3>
            <div class="number">$inactiveApps</div>
            <div class="subtitle">No activity in 30+ days</div>
        </div>
        <div class="summary-card">
            <h3>🧹 Cleanup Candidates</h3>
            <div class="number">$cleanupCandidates</div>
            <div class="subtitle">Apps recommended for review/removal</div>
        </div>
        <div class="summary-card">
            <h3>🔧 Application Permissions</h3>
            <div class="number">$totalApplicationPerms</div>
            <div class="subtitle">High-risk daemon permissions ($appsWithApplicationPerms apps)</div>
        </div>
        <div class="summary-card">
            <h3>👤 Delegated Permissions</h3>
            <div class="number">$totalDelegatedPerms</div>
            <div class="subtitle">User-context permissions ($appsWithDelegatedPerms apps)</div>
        </div>
    </div>

    <div class="controls">
        <h3>🔍 Search and Filter</h3>
        <input type="text" id="searchInput" placeholder="Search by app name..." onkeyup="filterTable()">
        <select id="riskFilter" onchange="filterTable()">
            <option value="">All Risk Levels</option>
            <option value="Critical">Critical Risk</option>
            <option value="High">High Risk</option>
            <option value="Medium">Medium Risk</option>
            <option value="Low">Low Risk</option>
        </select>
        <select id="appTypeFilter" onchange="filterTable()">
            <option value="">All App Types</option>
            <option value="true">With App Registration</option>
            <option value="false">Service Principal Only</option>
        </select>
        <select id="permissionTypeFilter" onchange="filterTable()">
            <option value="">All Permission Types</option>
            <option value="application">Apps with Application Permissions</option>
            <option value="delegated">Apps with Delegated Permissions</option>
            <option value="both">Apps with Both Types</option>
            <option value="none">Apps with No Permissions</option>
        </select>
        <select id="cleanupFilter" onchange="filterTable()">
            <option value="">All Cleanup Recommendations</option>
            <option value="Immediate Review Required">Immediate Review</option>
            <option value="Consider Removal">Consider Removal</option>
            <option value="Review Required">Review Required</option>
            <option value="Keep">Keep</option>
        </select>
        <button onclick="sortTable(4, 'number')">Sort by Risk Score</button>
        <button onclick="sortTable(6, 'number')">Sort by Total Permissions</button>
        <button onclick="clearFilters()">Clear All Filters</button>
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'string')">Application Name</th>
                <th onclick="sortTable(1, 'string')">App ID</th>
                <th onclick="sortTable(2, 'string')">App Type</th>
                <th onclick="sortTable(3, 'string')">Has App Registration</th>
                <th onclick="sortTable(4, 'number')">Risk Score</th>
                <th onclick="sortTable(5, 'string')">Risk Level</th>
                <th onclick="sortTable(6, 'number')">Total Permissions</th>
                <th>Permissions</th>
                <th onclick="sortTable(8, 'string')">Cleanup Recommendation</th>
                <th onclick="sortTable(9, 'string')">Sign-in Activity</th>
                <th onclick="sortTable(10, 'number')">Active Credentials</th>
                <th>Risk Factors</th>
            </tr>
        </thead>
        <tbody>
"@

# Sort by risk score (descending) and then by cleanup recommendation priority
$sortedReport = $enhancedReport | Sort-Object @{Expression="RiskScore"; Descending=$true}, @{Expression={
    switch ($_.CleanupRecommendation) {
        "Immediate Review Required" { 1 }
        "Consider Removal" { 2 }
        "Review Required" { 3 }
        "Keep" { 4 }
        default { 5 }
    }
}}

foreach ($app in $sortedReport) {
    $riskClass = "risk-" + $app.RiskLevel.ToLower()
    $appRegClass = if ($app.HasAppRegistration) { "has-app-reg" } else { "sp-only" }
    $appRegText = if ($app.HasAppRegistration) { "✅ Yes" } else { "❌ No" }
    
    $cleanupClass = switch ($app.CleanupRecommendation) {
        "Immediate Review Required" { "cleanup-immediate" }
        "Consider Removal" { "cleanup-consider" }
        "Review Required" { "cleanup-review" }
        "Keep" { "cleanup-keep" }
        default { "cleanup-keep" }
    }
    
    $credentialsInfo = ""
    if ($app.HasAppRegistration) {
        $credentialsInfo = "🔑 $($app.ActiveSecrets) secrets, 📜 $($app.ActiveCertificates) certs"
        if ($app.ExpiringCredentials -gt 0) {
            $credentialsInfo += " (⚠️ $($app.ExpiringCredentials) expiring)"
        }
    } else {
        $credentialsInfo = "N/A (Service Principal Only)"
    }
    
    # Sign-in status with appropriate styling
    $signInClass = switch ($app.SignInStatus) {
        "Sign-ins found" { "signin-found" }
        "No sign-ins found" { "signin-notfound" }
        "Not checked" { "signin-notchecked" }
        default { "signin-notchecked" }
    }
    
    # Build permission details with clear type indicators
    $permissionDetails = ""
    foreach ($perm in $app.Permissions) {
        $permClass = switch ($perm.Type) {
            "Application" { "app-permission" }
            "Delegated" { "delegated-permission" }
            "Directory Role" { "directory-role" }
        }
        $permissionDetails += "<div class='permission-item $permClass'><strong>[$($perm.Type)]</strong> $($perm.Permission) on <em>$($perm.Resource)</em></div>"
    }
    
    # Build risk factors without permission details
    $riskFactorsHtml = ($app.RiskFactors | Where-Object { 
        $_ -notmatch "permission:" -and $_ -notmatch "Directory role:"
    } | ForEach-Object { "<li>$_</li>" }) -join ""
    $riskFactorsHtml = if ($riskFactorsHtml) { "<ul style='margin:5px 0; padding-left: 20px;'>$riskFactorsHtml</ul>" } else { "No specific risk factors identified" }
    
    $cleanupReasonHtml = if ($app.CleanupReason) { "<p><strong>Reason:</strong> $($app.CleanupReason)</p>" } else { "" }
    
    $html += @"
            <tr class="$riskClass" data-risk="$($app.RiskLevel)" data-apptype="$($app.HasAppRegistration)" data-cleanup="$($app.CleanupRecommendation)" data-apppermcount="$($app.ApplicationPermissions)" data-delegatedpermcount="$($app.DelegatedPermissions)">
                <td><strong>$($app.DisplayName)</strong></td>
                <td><code style='font-size: 10px;'>$($app.AppId)</code></td>
                <td>$($app.AppType)</td>
                <td class="$appRegClass">$appRegText</td>
                <td><strong>$($app.RiskScore)</strong></td>
                <td><span class="$riskClass">$($app.RiskLevel)</span></td>
                <td><strong>$($app.TotalPermissions)</strong></td>
                <td style='font-size: 11px;'>
                    <details>
                        <summary><strong>Permissions ($($app.TotalPermissions))</strong></summary>
                        <div class="permission-list">$permissionDetails</div>
                    </details>
                </td>
                <td><span class="$cleanupClass">$($app.CleanupRecommendation)</span></td>
                <td><span class="$signInClass">$($app.SignInStatus)</span></td>
                <td style='font-size: 11px;'>$credentialsInfo</td>
                <td style='font-size: 11px;'>
                    <details open>
                        <summary><strong>Risk Factors</strong></summary>
                        $riskFactorsHtml
                        $cleanupReasonHtml
                    </details>
                </td>
            </tr>
"@
}

$html += @"
        </tbody>
    </table>

    <script>
        function filterTable() {
            const searchInput = document.getElementById('searchInput').value.toLowerCase();
            const riskFilter = document.getElementById('riskFilter').value;
            const appTypeFilter = document.getElementById('appTypeFilter').value;
            const permissionTypeFilter = document.getElementById('permissionTypeFilter').value;
            const cleanupFilter = document.getElementById('cleanupFilter').value;
            const table = document.getElementById('reportTable');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const appName = row.cells[0].textContent.toLowerCase();
                const riskLevel = row.getAttribute('data-risk');
                const hasAppReg = row.getAttribute('data-apptype');
                const cleanupRec = row.getAttribute('data-cleanup');
                const applicationPerms = parseInt(row.getAttribute('data-apppermcount')) || 0;
                const delegatedPerms = parseInt(row.getAttribute('data-delegatedpermcount')) || 0;
                
                let show = true;
                
                if (searchInput && !appName.includes(searchInput)) show = false;
                if (riskFilter && riskLevel !== riskFilter) show = false;
                if (appTypeFilter && hasAppReg !== appTypeFilter) show = false;
                if (cleanupFilter && cleanupRec !== cleanupFilter) show = false;
                
                // Permission type filtering
                if (permissionTypeFilter) {
                    switch(permissionTypeFilter) {
                        case 'application':
                            if (applicationPerms === 0) show = false;
                            break;
                        case 'delegated':
                            if (delegatedPerms === 0) show = false;
                            break;
                        case 'both':
                            if (applicationPerms === 0 || delegatedPerms === 0) show = false;
                            break;
                        case 'none':
                            if (applicationPerms > 0 || delegatedPerms > 0) show = false;
                            break;
                    }
                }
                
                row.style.display = show ? '' : 'none';
            });
        }
        
        function sortTable(columnIndex, type) {
            const table = document.getElementById('reportTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                if (type === 'number') {
                    aVal = parseInt(aVal.replace(/[^0-9]/g, '')) || 0;
                    bVal = parseInt(bVal.replace(/[^0-9]/g, '')) || 0;
                    return bVal - aVal; // Descending for numbers
                }
                
                return aVal.localeCompare(bVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function clearFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('riskFilter').value = '';
            document.getElementById('appTypeFilter').value = '';
            document.getElementById('permissionTypeFilter').value = '';
            document.getElementById('cleanupFilter').value = '';
            filterTable();
        }
    </script>

    <div class="footer">
        <p><strong>Legend:</strong></p>
        <p>✅ <strong>With App Registration:</strong> Custom/third-party apps with full App Registration objects</p>
        <p>❌ <strong>Service Principal Only:</strong> Pre-authorized apps, gallery apps, or system-created principals without App Registrations</p>
        <p>🟢 <strong>Sign-ins found:</strong> Sign-in activity detected in the last 30 days</p>
        <p>🔴 <strong>No sign-ins found:</strong> No sign-in activity detected in the last 30 days</p>
        <p>🟡 <strong>Not checked:</strong> Sign-in logs were not requested (use -IncludeSignInLogs parameter)</p>
        <p>🔧 <strong>Application Permissions:</strong> High-risk daemon permissions that run with app identity</p>
        <p>👤 <strong>Delegated Permissions:</strong> User-context permissions limited by user's actual access</p>
        <br>
        <p>Found this tool helpful? Subscribe to my blog at <a href="https://www.matej.guru" target="_blank" style="color: #00abeb; text-decoration: none;">www.matej.guru</a>.</p>
        <p style="margin-top: 10px; font-size: 0.8em; color: #95a5a6;">This script is provided "as is", without any warranty. Data provided by ip-api.com</p>
    </div>
</body>
</html>
"@

# Save the enhanced HTML report
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Enhanced report generated successfully: $OutputPath" -ForegroundColor Green
Write-Host "Opening report in default browser..." -ForegroundColor Green

# Open the report in default browser
Start-Process $OutputPath

# Display summary statistics in console
Write-Host "`n=== ENHANCED REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Applications: $totalApps" -ForegroundColor White
Write-Host "  - With App Registrations: $appsWithRegistrations" -ForegroundColor Green
Write-Host "  - Service Principals Only: $servicePrincipalsOnly" -ForegroundColor Yellow
Write-Host "`nPermission Analysis:" -ForegroundColor White
Write-Host "  - Apps with Application Permissions: $appsWithApplicationPerms (Total: $totalApplicationPerms)" -ForegroundColor Red
Write-Host "  - Apps with Delegated Permissions: $appsWithDelegatedPerms (Total: $totalDelegatedPerms)" -ForegroundColor Green
Write-Host "`nRisk Assessment:" -ForegroundColor White
Write-Host "  - Critical Risk: $criticalRiskApps" -ForegroundColor Red
Write-Host "  - High Risk: $highRiskApps" -ForegroundColor DarkYellow
Write-Host "  - Medium Risk: $(($enhancedReport | Where-Object { $_.RiskLevel -eq "Medium" }).Count)" -ForegroundColor Yellow
Write-Host "  - Low Risk: $(($enhancedReport | Where-Object { $_.RiskLevel -eq "Low" }).Count)" -ForegroundColor Green
Write-Host "`nCleanup Analysis:" -ForegroundColor White
Write-Host "  - Immediate Review Required: $(($enhancedReport | Where-Object { $_.CleanupRecommendation -eq "Immediate Review Required" }).Count)" -ForegroundColor Red
Write-Host "  - Consider Removal: $(($enhancedReport | Where-Object { $_.CleanupRecommendation -eq "Consider Removal" }).Count)" -ForegroundColor DarkYellow
Write-Host "  - Review Required: $(($enhancedReport | Where-Object { $_.CleanupRecommendation -eq "Review Required" }).Count)" -ForegroundColor Yellow
Write-Host "  - Keep: $(($enhancedReport | Where-Object { $_.CleanupRecommendation -eq "Keep" }).Count)" -ForegroundColor Green
Write-Host "`nActivity Analysis:" -ForegroundColor White
Write-Host "  - Inactive Apps ($InactiveThresholdDays+ days): $inactiveApps" -ForegroundColor Yellow
Write-Host "  - Apps without credentials: $(($enhancedReport | Where-Object { $_.HasActiveCredentials -eq $false -and $_.HasAppRegistration -eq $true }).Count)" -ForegroundColor DarkYellow

# Performance summary
if ($IncludeSignInLogs -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly)) {
    Write-Host "`n🚀 Performance Optimization:" -ForegroundColor Green
    Write-Host "  - Pre-filtering optimization was applied" -ForegroundColor Green
    Write-Host "  - Sign-in logs were only retrieved for filtered applications" -ForegroundColor Green
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Host "`nScript completed successfully!" -ForegroundColor Green
Write-Host "Check the HTML report for detailed analysis and interactive filtering." -ForegroundColor Cyan
