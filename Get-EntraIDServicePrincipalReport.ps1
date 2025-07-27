<#
.SYNOPSIS
    Generates an interactive HTML report of Microsoft Entra ID Service Principals (Enterprise Applications) with risk assessment.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves service principals matching the Enterprise Applications filter, analyzes permissions and credentials.
    It calculates a risk score based on configurable rules and produces an optimized, filterable HTML report.
    Focuses on reliable data without attempting complex activity detection.

.AUTHOR
    Matej Klemencic (www.matej.guru)

.NOTES
    Version:        1.1
    Last Modified:  2025-07-27

.PARAMETER OutputPath
    Path to save the generated HTML report. Defaults to "EntraIDServicePrincipalReport.html".

.PARAMETER OnlyWithPermissions
    Include only service principals that have at least one permission (delegated, application or directory role).

.PARAMETER MinimumPermissions
    Include only service principals with total permissions count >= this number. Default is 0 (no minimum).

.PARAMETER RiskConfigPath
    Path to a JSON file with custom risk scoring configuration. If provided and valid, overrides default risk rules.

.PARAMETER OnlyWithAppRegistrations
    Include only applications that have corresponding App Registration objects in the tenant.

.PARAMETER OnlyServicePrincipalsOnly
    Include only service principals without an App Registration (e.g., gallery or legacy apps).

.PARAMETER Verbose
    Enable verbose logging for troubleshooting.

.EXAMPLE
    # Generate simplified report
    .\Get-EntraIDServicePrincipalReport.ps1

.EXAMPLE
    # Include only apps with registrations and verbose logging
    .\Get-EntraIDServicePrincipalReport.ps1 -OnlyWithAppRegistrations -Verbose

.EXAMPLE
    # List only SPs with at least 5 permissions
    .\Get-EntraIDServicePrincipalReport.ps1 -MinimumPermissions 5
    
.INSTALLATION
    Install the required Microsoft Graph modules:

    # Install only necessary modules
    Install-Module -Name Microsoft.Graph.Authentication,Microsoft.Graph.Applications,Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.DirectoryManagement,Microsoft.Graph.Reports -Scope CurrentUser -AllowClobber

    # Or install the full umbrella module
    Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber
#>
param(
    [string]$OutputPath = "EntraIDServicePrincipalReport.html",
    [switch]$OnlyWithPermissions,
    [int]$MinimumPermissions = 0,
    [string]$RiskConfigPath = $null,
    [switch]$OnlyWithAppRegistrations,
    [switch]$OnlyServicePrincipalsOnly,
    [switch]$Verbose
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

# Function to calculate risk score (simplified - no activity-based scoring)
function Get-RiskScore {
    param(
        [array]$Permissions,
        [array]$DirectoryRoles,
        [string]$DisplayName,
        [string]$PublisherName,
        [bool]$HasCredentials,
        [bool]$HasAppRegistration,
        $TotalUsers
    )
    
    $score = 0
    $riskFactors = @()
    
    # Permission-based scoring - track unique permissions to avoid double counting
    $uniqueHighRiskPerms = @()
    $uniqueMediumRiskPerms = @()
    $hasApplicationPerms = $false
    
    foreach ($perm in $Permissions) {
        # Track application permissions separately
        if ($perm.Type -eq "Application") {
            $hasApplicationPerms = $true
        }
        
        # Only count each unique permission once
        if ($perm.Permission -in $riskConfig.HighRiskPermissions -and $perm.Permission -notin $uniqueHighRiskPerms) {
            $score += 10
            $uniqueHighRiskPerms += $perm.Permission
            $riskFactors += "High-risk permission: $($perm.Permission)"
        }
        elseif ($perm.Permission -in $riskConfig.MediumRiskPermissions -and $perm.Permission -notin $uniqueMediumRiskPerms) {
            $score += 5
            $uniqueMediumRiskPerms += $perm.Permission
            $riskFactors += "Medium-risk permission: $($perm.Permission)"
        }
    }
    
    # Application permissions bonus (only once, not per permission)
    if ($hasApplicationPerms) {
        $score += 5
        $riskFactors += "Has application (daemon) permissions"
    }
    
    # Directory role scoring - only count unique roles
    $uniqueRoles = @()
    foreach ($role in $DirectoryRoles) {
        if ($role.Permission -notin $uniqueRoles) {
            $uniqueRoles += $role.Permission
            if ($role.Permission -in $riskConfig.HighRiskDirectoryRoles) {
                $score += 15
                $riskFactors += "High-risk directory role: $($role.Permission)"
            }
            else {
                $score += 8
                $riskFactors += "Directory role: $($role.Permission)"
            }
        }
    }
    
    # Suspicious naming (only check once)
    $suspiciousKeywords = @()
    foreach ($keyword in $riskConfig.SuspiciousKeywords) {
        if ($DisplayName -ilike "*$keyword*" -and $keyword -notin $suspiciousKeywords) {
            $suspiciousKeywords += $keyword
        }
    }
    if ($suspiciousKeywords.Count -gt 0) {
        $score += 5
        $riskFactors += "Suspicious name contains: $($suspiciousKeywords -join ', ')"
    }
    
    # Unknown publisher (only check once)
    if ([string]::IsNullOrEmpty($PublisherName) -or $PublisherName -eq "Unknown") {
        $score += 3
        $riskFactors += "Unknown or missing publisher"
    }
    
    # High user count with sensitive permissions (only check once)
    if ($TotalUsers -eq "All Users" -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 5
        $riskFactors += "Sensitive permissions with all users access"
    }
    elseif ($TotalUsers -is [int] -and $TotalUsers -gt 50 -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 3
        $riskFactors += "Sensitive permissions affecting many users ($TotalUsers users)"
    }
    
    # No active credentials (only for apps with registrations, check once)
    if (-not $HasCredentials -and $HasAppRegistration) {
        $score += 4
        $riskFactors += "No active credentials/certificates"
    }
    
    # Service Principal without App Registration (check once)
    if (-not $HasAppRegistration) {
        $score += 2
        $riskFactors += "Service Principal without App Registration"
    }
    
    return @{
        Score = $score
        Level = if ($score -ge 30) { "Critical" } elseif ($score -ge 20) { "High" } elseif ($score -ge 10) { "Medium" } else { "Low" }
        Factors = $riskFactors
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
Import-GraphModuleSafely "Microsoft.Graph.Identity.DirectoryManagement"

# Connect to Microsoft Graph
$scopes = @(
    "Application.Read.All",
    "Directory.Read.All", 
    "DelegatedPermissionGrant.Read.All",
    "RoleManagement.Read.Directory"
)

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

# PRE-FILTERING PHASE: Apply quick filters first for performance optimization
if ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly) {
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
    Write-Host "Performance gain: Skipping detailed analysis for $($servicePrincipals.Count - $filteredServicePrincipals.Count) applications" -ForegroundColor Yellow
    
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

Write-Host "`nProceeding with analysis..." -ForegroundColor Green

$report = @()
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
    
    # Get application credentials
    $credentials = Get-ApplicationCredentials -AppId $sp.AppId
    
    # Calculate total users affected
    $totalUsersAffected = if ($permissionInfo.DelegatedGrants | Where-Object { $_.ConsentType -eq "AllPrincipals" }) { 
        "All Users" 
    } else { 
        $totalUsers
    }
    
    # Calculate risk score (simplified - no activity data)
    $riskAssessment = Get-RiskScore -Permissions $permissions -DirectoryRoles ($permissionInfo.RoleAssignments | ForEach-Object { @{Permission = $_.DisplayName} }) -DisplayName $sp.DisplayName -PublisherName $sp.PublisherName -HasCredentials $credentials.HasActiveCredentials -HasAppRegistration $credentials.HasAppRegistration -TotalUsers $totalUsersAffected
    
    $report += [PSCustomObject]@{
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
        
        # Credentials
        HasActiveCredentials = $credentials.HasActiveCredentials
        ActiveSecrets = $credentials.ActiveSecrets
        ActiveCertificates = $credentials.ActiveCertificates
        ExpiringCredentials = $credentials.ExpiringCredentials
        
        # Risk assessment
        RiskScore = $riskAssessment.Score
        RiskLevel = $riskAssessment.Level
        RiskFactors = $riskAssessment.Factors
        
        # Other fields
        TotalUsers = $totalUsersAffected
        ServicePrincipalType = $sp.ServicePrincipalType
        SignInAudience = $sp.SignInAudience
    }
}

Write-Progress -Activity "Processing applications" -Completed

# Apply remaining filters (if not already applied during pre-filtering)
Write-Host "Applying final filters..." -ForegroundColor Green

if ($OnlyWithPermissions) {
    $report = $report | Where-Object { $_.TotalPermissions -gt 0 }
}

if ($OnlyWithAppRegistrations) {
    $report = $report | Where-Object { $_.HasAppRegistration -eq $true }
}

if ($OnlyServicePrincipalsOnly) {
    $report = $report | Where-Object { $_.HasAppRegistration -eq $false }
}

if ($MinimumPermissions -gt 0) {
    $report = $report | Where-Object { $_.TotalPermissions -ge $MinimumPermissions }
}

Write-Host "Final report contains $($report.Count) applications" -ForegroundColor Green

# Calculate summary statistics
$totalApps = $report.Count
$appsWithRegistrations = ($report | Where-Object { $_.HasAppRegistration -eq $true }).Count
$servicePrincipalsOnly = ($report | Where-Object { $_.HasAppRegistration -eq $false }).Count
$criticalRiskApps = ($report | Where-Object { $_.RiskLevel -eq "Critical" }).Count
$highRiskApps = ($report | Where-Object { $_.RiskLevel -eq "High" }).Count
$appsWithApplicationPerms = ($report | Where-Object { $_.ApplicationPermissions -gt 0 }).Count
$appsWithDelegatedPerms = ($report | Where-Object { $_.DelegatedPermissions -gt 0 }).Count
$totalApplicationPerms = ($report | Measure-Object -Property ApplicationPermissions -Sum).Sum
$totalDelegatedPerms = ($report | Measure-Object -Property DelegatedPermissions -Sum).Sum
$appsWithoutCredentials = ($report | Where-Object { $_.HasActiveCredentials -eq $false -and $_.HasAppRegistration -eq $true }).Count

# Get tenant information
$tenantInfo = Get-MgOrganization | Select-Object -First 1
$tenantName = $tenantInfo.DisplayName
$tenantId = $tenantInfo.Id

# Generate simplified HTML report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Entra ID Service Principals Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background-color: #f8f9fa; }
        .header { background-color: #00abeb; color: #ffffff; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
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
        .permission-list { max-height: 200px; overflow-y: auto; font-size: 11px; }
        .permission-item { margin: 2px 0; padding: 2px 5px; background: #e2e8f0; border-radius: 3px; display: inline-block; margin-right: 5px; }
        .app-permission { background: #fed7d7; color: #c53030; font-weight: bold; }
        .delegated-permission { background: #c6f6d5; color: #38a169; }
        .directory-role { background: #feebc8; border-left: 3px solid #dd6b20; color: #dd6b20; font-weight: bold; }
        .footer { margin-top: 30px; padding: 20px; text-align: center; color: #718096; background: white; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Entra ID Service Principals Report</h1>
        <p><strong>Tenant:</strong> $tenantName</p>
        <p><strong>Tenant ID:</strong> $tenantId</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>

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
            <h3>🔧 Application Permissions</h3>
            <div class="number">$totalApplicationPerms</div>
            <div class="subtitle">High-risk daemon permissions ($appsWithApplicationPerms apps)</div>
        </div>
        <div class="summary-card">
            <h3>👤 Delegated Permissions</h3>
            <div class="number">$totalDelegatedPerms</div>
            <div class="subtitle">User-context permissions ($appsWithDelegatedPerms apps)</div>
        </div>
        <div class="summary-card">
            <h3>🔑 Without Credentials</h3>
            <div class="number">$appsWithoutCredentials</div>
            <div class="subtitle">Apps with registrations but no active credentials</div>
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
            <option value="Web/SPA App">Web/SPA Apps</option>
            <option value="Mobile/Desktop App">Mobile/Desktop Apps</option>
            <option value="Daemon/Service App">Daemon/Service Apps</option>
            <option value="Service Principal Only">Service Principal Only</option>
            <option value="Unknown App Type">Unknown App Type</option>
        </select>
        <select id="permissionTypeFilter" onchange="filterTable()">
            <option value="">All Permission Types</option>
            <option value="application">Apps with Application Permissions</option>
            <option value="delegated">Apps with Delegated Permissions</option>
            <option value="both">Apps with Both Types</option>
            <option value="none">Apps with No Permissions</option>
        </select>
        <button onclick="sortTable(4, 'number')">Sort by Risk Score</button>
        <button onclick="sortTable(5, 'number')">Sort by Total Permissions</button>
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
                <th>Permissions Detail</th>
                <th onclick="sortTable(8, 'string')">Publisher</th>
                <th onclick="sortTable(9, 'string')">Active Credentials</th>
                <th>Risk Factors</th>
            </tr>
        </thead>
        <tbody>
"@

# Sort by risk score (descending), then by total permissions (descending)
$sortedReport = $report | Sort-Object @{Expression="RiskScore"; Descending=$true}, @{Expression="TotalPermissions"; Descending=$true}

foreach ($app in $sortedReport) {
    $riskClass = "risk-" + $app.RiskLevel.ToLower()
    $appRegClass = if ($app.HasAppRegistration) { "has-app-reg" } else { "sp-only" }
    $appRegText = if ($app.HasAppRegistration) { "✅ Yes" } else { "❌ No" }
    
    $credentialsInfo = ""
    $credentialStatus = ""
    if ($app.HasAppRegistration) {
        $credentialsInfo = "🔑 $($app.ActiveSecrets) secrets, 📜 $($app.ActiveCertificates) certs"
        if ($app.ExpiringCredentials -gt 0) {
            $credentialsInfo += " (⚠️ $($app.ExpiringCredentials) expiring)"
        }
        $credentialStatus = if ($app.HasActiveCredentials) { "✅ Active" } else { "❌ None" }
    } else {
        $credentialsInfo = "N/A (Service Principal Only)"
        $credentialStatus = "N/A"
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
    
    # Build risk factors - the array should already be deduplicated from Get-RiskScore function
    $riskFactorsHtml = if ($app.RiskFactors.Count -gt 0) {
        $riskFactorItems = ($app.RiskFactors | ForEach-Object { "<li>$_</li>" }) -join ""
        "<ul style='margin:5px 0; padding-left: 20px;'>$riskFactorItems</ul>"
    } else {
        "No specific risk factors identified"
    }
    
    # Permission breakdown for summary
    $permissionSummary = "App: $($app.ApplicationPermissions), Delegated: $($app.DelegatedPermissions), Roles: $($app.DirectoryRoles)"
    
    $html += @"
            <tr class="$riskClass" data-risk="$($app.RiskLevel)" data-apptype="$($app.HasAppRegistration)" data-apppermcount="$($app.ApplicationPermissions)" data-delegatedpermcount="$($app.DelegatedPermissions)" data-credentials="$($app.HasActiveCredentials)">
                <td><strong>$($app.DisplayName)</strong></td>
                <td><code style='font-size: 10px;'>$($app.AppId)</code></td>
                <td>$($app.AppType)</td>
                <td class="$appRegClass">$appRegText</td>
                <td><strong>$($app.RiskScore)</strong></td>
                <td><span class="$riskClass">$($app.RiskLevel)</span></td>
                <td><strong>$($app.TotalPermissions)</strong><br><small style='color: #666;'>$permissionSummary</small></td>
                <td style='font-size: 11px;'>
                    <details>
                        <summary><strong>View Permissions ($($app.TotalPermissions))</strong></summary>
                        <div class="permission-list">$permissionDetails</div>
                    </details>
                </td>
                <td>$(if ($app.PublisherName) { $app.PublisherName } else { "<em>Unknown</em>" })</td>
                <td style='font-size: 11px;'>
                    <strong>$credentialStatus</strong><br>
                    $credentialsInfo
                </td>
                <td style='font-size: 11px;'>
                    <details>
                        <summary><strong>Risk Analysis ($($app.RiskFactors.Count))</strong></summary>
                        $riskFactorsHtml
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
            const table = document.getElementById('reportTable');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const appName = row.cells[0].textContent.toLowerCase();
                const riskLevel = row.getAttribute('data-risk');
                const appType = row.cells[2].textContent.trim(); // App Type column
                const applicationPerms = parseInt(row.getAttribute('data-apppermcount')) || 0;
                const delegatedPerms = parseInt(row.getAttribute('data-delegatedpermcount')) || 0;
                
                let show = true;
                
                if (searchInput && !appName.includes(searchInput)) show = false;
                if (riskFilter && riskLevel !== riskFilter) show = false;
                if (appTypeFilter && appType !== appTypeFilter) show = false;
                
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
            filterTable();
        }
    </script>

    <div class="footer">
        <p><strong>Legend:</strong></p>
        <p>✅ <strong>With App Registration:</strong> Custom/third-party apps with full App Registration objects</p>
        <p>❌ <strong>Service Principal Only:</strong> Pre-authorized apps, gallery apps, or system-created principals without App Registrations</p>
        <p>🔧 <strong>Application Permissions:</strong> High-risk daemon permissions that run with app identity</p>
        <p>👤 <strong>Delegated Permissions:</strong> User-context permissions limited by user's actual access</p>
        <p>🔑 <strong>Active Credentials:</strong> Applications with valid secrets or certificates</p>
        <br>
        <p>Found this tool helpful? Subscribe to my blog at <a href="https://www.matej.guru" target="_blank" style="color: #00abeb; text-decoration: none;">www.matej.guru</a>.</p>
        <p style="margin-top: 10px; font-size: 0.8em; color: #95a5a6;">This script is provided "as is", without any warranty.</p>
    </div>
</body>
</html>
"@

# Save the simplified HTML report
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Simplified report generated successfully: $OutputPath" -ForegroundColor Green
Write-Host "Opening report in default browser..." -ForegroundColor Green

# Open the report in default browser
Start-Process $OutputPath

# Display summary statistics in console
Write-Host "`n=== SIMPLIFIED REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Applications: $totalApps" -ForegroundColor White
Write-Host "  - With App Registrations: $appsWithRegistrations" -ForegroundColor Green
Write-Host "  - Service Principals Only: $servicePrincipalsOnly" -ForegroundColor Yellow
Write-Host "`nPermission Analysis:" -ForegroundColor White
Write-Host "  - Apps with Application Permissions: $appsWithApplicationPerms (Total: $totalApplicationPerms)" -ForegroundColor Red
Write-Host "  - Apps with Delegated Permissions: $appsWithDelegatedPerms (Total: $totalDelegatedPerms)" -ForegroundColor Green
Write-Host "`nRisk Assessment:" -ForegroundColor White
Write-Host "  - Critical Risk: $criticalRiskApps" -ForegroundColor Red
Write-Host "  - High Risk: $highRiskApps" -ForegroundColor DarkYellow
Write-Host "  - Medium Risk: $(($report | Where-Object { $_.RiskLevel -eq "Medium" }).Count)" -ForegroundColor Yellow
Write-Host "  - Low Risk: $(($report | Where-Object { $_.RiskLevel -eq "Low" }).Count)" -ForegroundColor Green
Write-Host "`nCredential Analysis:" -ForegroundColor White
Write-Host "  - Apps with active credentials: $(($report | Where-Object { $_.HasActiveCredentials -eq $true }).Count)" -ForegroundColor Green
Write-Host "  - Apps without credentials: $appsWithoutCredentials" -ForegroundColor DarkYellow
Write-Host "  - Apps with expiring credentials (30 days): $(($report | Where-Object { $_.ExpiringCredentials -gt 0 }).Count)" -ForegroundColor Yellow

# Simplified summary
Write-Host "`n📊 Simplified Approach:" -ForegroundColor Green
Write-Host "  - Removed unreliable activity detection" -ForegroundColor Green
Write-Host "  - Focus on permissions, credentials, and risk assessment" -ForegroundColor Green
Write-Host "  - Manual sign-in log review recommended for usage verification" -ForegroundColor Yellow

# Performance summary
if ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipalsOnly) {
    Write-Host "`n⚡ Performance Optimization:" -ForegroundColor Green
    Write-Host "  - Pre-filtering optimization was applied" -ForegroundColor Green
    Write-Host "  - Analysis was only performed on filtered applications" -ForegroundColor Green
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Host "`nScript completed successfully!" -ForegroundColor Green
Write-Host "Check the HTML report for detailed analysis focused on reliable data." -ForegroundColor Cyan
Write-Host "For usage verification, manually review sign-in logs in the Azure portal." -ForegroundColor Yellow
