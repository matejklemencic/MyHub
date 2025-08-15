<#
.SYNOPSIS
    Generates comprehensive reports of Microsoft Entra ID Guest Users with activity analysis and cleanup recommendations.

.DESCRIPTION
    This script connects to Microsoft Entra ID, retrieves all guest users (both cloud-only and on-premises synced), and analyzes their activity patterns.
    It generates both CSV and HTML reports by default, providing detailed insights into guest user status, sign-in activity, and account health.
    The script identifies inactive accounts, pending invitations, and users who never signed in to help with guest user lifecycle management.

.AUTHOR
    Matej Klemenčič

.NOTES
    Version:        2.0
    Last Modified:  2025-08-15

.PARAMETER TenantId
    Optional TenantId for connecting to Entra. If not provided, will use the current user's tenant.

.PARAMETER PendingAcceptanceOnly
    If set, only export guests with an externalUserState of "PendingAcceptance".

.PARAMETER InactiveDays
    Number of days to consider a user as "inactive" (default: 90 days).

.PARAMETER ExportPath
    Export path (default: script location).

.PARAMETER FileName
    Custom filename (without extension).

.PARAMETER CSVOnly
    Generate only CSV report (default: both HTML and CSV).

.PARAMETER HTMLOnly
    Generate only HTML report (default: both HTML and CSV).

.EXAMPLE
    # Generate both HTML and CSV reports with default settings
    .\Export-EntraGuestReport.ps1

.EXAMPLE
    # Generate only CSV report for pending guests
    .\Export-EntraGuestReport.ps1 -PendingAcceptanceOnly -CSVOnly

.EXAMPLE
    # Custom inactive threshold and HTML report only
    .\Export-EntraGuestReport.ps1 -InactiveDays 180 -HTMLOnly

.EXAMPLE
    # Custom path and filename for both reports
    .\Export-EntraGuestReport.ps1 -ExportPath "D:\Reports" -FileName "MonthlyGuestAudit"

.INSTALLATION
    Install the required Microsoft Entra PowerShell module:

    # Install the Entra PowerShell module
    Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber

#>

param(
    # Optional TenantId for connecting to Entra. If not provided, will use the current user's tenant.
    [string]$TenantId,
    
    # If set, only export guests with an externalUserState of "PendingAcceptance"
    [switch]$PendingAcceptanceOnly,
    
    # Number of days to consider a user as "inactive" (default: 90 days)
    [int]$InactiveDays = 90,
    
    # Export path (default: script location)
    [string]$ExportPath,
    
    # Custom filename (without extension)
    [string]$FileName,
    
    # Generate only CSV report (default: both HTML and CSV)
    [switch]$CSVOnly,
    
    # Generate only HTML report (default: both HTML and CSV)
    [switch]$HTMLOnly
)

# Connect to Entra ID (Azure AD) with the required scope.
try {
    if ($TenantId) {
        Connect-Entra -Scopes 'User.Read.All' -TenantId $TenantId
        Write-Output "Successfully connected to Entra ID with specified tenant: $TenantId"
    } else {
        Connect-Entra -Scopes 'User.Read.All'
        Write-Output "Successfully connected to Entra ID with current user's tenant"
    }
}
catch {
    Write-Error "Failed to connect to Entra ID: $_"
    exit 1
}

# Calculate the cutoff date for inactive users
$inactiveCutoffDate = (Get-Date).AddDays(-$InactiveDays)

Write-Output "Retrieving guest users from Entra ID..."

# Retrieve all guest users from Entra ID with comprehensive properties
$guests = Get-EntraUser -Filter "userType eq 'Guest'" -All -Property @(
    'UserPrincipalName', 
    'Mail',
    'CreatedDateTime',
    'SignInActivity',
    'ExternalUserState',
    'ExternalUserStateChangeDateTime',
    'OnPremisesSyncEnabled',
    'AccountEnabled',
    'LastPasswordChangeDateTime',
    'UserType'
)

Write-Output "Found $($guests.Count) total guest users"

# Process all guests (both cloud-only and on-premises synced)
$allGuests = $guests
Write-Output "Processing all $($allGuests.Count) guest users (both cloud-only and on-premises synced)"

# If the PendingAcceptanceOnly switch is set, filter to only include guests with a PendingAcceptance state
if ($PendingAcceptanceOnly) {
    $allGuests = $allGuests | Where-Object { $_.ExternalUserState -eq "PendingAcceptance" }
    Write-Output "Filtered to $($allGuests.Count) guests with PendingAcceptance state"
}

# Get the current date formatted as YYYYMMDD
$exportDate = Get-Date -Format "yyyyMMdd"

# Set default export path to script location if not provided
if (-not $ExportPath) {
    $ExportPath = $PSScriptRoot
    if (-not $ExportPath) {
        # Fallback if $PSScriptRoot is not available (e.g., running interactively)
        $ExportPath = (Get-Location).Path
    }
}

# Retrieve the tenant's display name
try {
    $tenantDetail = Get-EntraTenantDetail
    $tenantName = $tenantDetail.DisplayName -replace '[\\/:*?"<>|]', '_'  # Replace invalid filename characters
    $tenantId = $tenantDetail.Id
}
catch {
    $tenantName = "Unknown_Tenant"
    $tenantId = "Unknown"
    Write-Warning "Could not retrieve tenant name, using default"
}

# Build the file names
if ($FileName) {
    $csvFileName = "$FileName.csv"
    $htmlFileName = "$FileName.html"
    $summaryFileName = "$FileName" + "_Summary.txt"
} else {
    $baseFileName = if ($PendingAcceptanceOnly) {
        "$tenantName" + "_PendingGuests_Report_" + "$exportDate"
    } else {
        "$tenantName" + "_AllGuests_Report_" + "$exportDate"
    }
    $csvFileName = "$baseFileName.csv"
    $htmlFileName = "$baseFileName.html"
    $summaryFileName = "$baseFileName" + "_Summary.txt"
}

# Build the full file paths
$csvPath = Join-Path $ExportPath $csvFileName
$htmlPath = Join-Path $ExportPath $htmlFileName

Write-Output "Processing guest user data..."

# Process and enhance the guest user data
$processedGuests = $allGuests | ForEach-Object {
    $guest = $_
    
    # Extract sign-in activity details
    $lastSuccessfulSignIn = $guest.SignInActivity.LastSuccessfulSignInDateTime
    $lastSignInRequest = $guest.SignInActivity.LastSignInDateTime
    $lastNonInteractiveSignIn = $guest.SignInActivity.LastNonInteractiveSignInDateTime
    
    # Determine the most recent activity date
    $mostRecentActivity = @($lastSuccessfulSignIn, $lastSignInRequest, $lastNonInteractiveSignIn) | 
        Where-Object { $_ -ne $null } | 
        Sort-Object -Descending | 
        Select-Object -First 1
    
    # Calculate days since last activity
    $daysSinceLastActivity = if ($mostRecentActivity) {
        [math]::Round(((Get-Date) - $mostRecentActivity).TotalDays, 0)
    } else {
        $null
    }
    
    # Calculate days since creation
    $daysSinceCreation = if ($guest.CreatedDateTime) {
        [math]::Round(((Get-Date) - $guest.CreatedDateTime).TotalDays, 0)
    } else {
        $null
    }
    
    # Calculate days since external user state change
    $daysSinceStateChange = if ($guest.ExternalUserStateChangeDateTime) {
        [math]::Round(((Get-Date) - $guest.ExternalUserStateChangeDateTime).TotalDays, 0)
    } else {
        $null
    }
    
    # Determine user status
    $userStatus = if ($guest.OnPremisesSyncEnabled) {
        "On-Premises Synced Guest"
    } else {
        switch ($guest.ExternalUserState) {
            "PendingAcceptance" { "Invitation Pending" }
            "Accepted" { 
                if ($mostRecentActivity -and $mostRecentActivity -lt $inactiveCutoffDate) {
                    "Inactive (Accepted but not used recently)"
                } elseif (-not $mostRecentActivity) {
                    "Never Signed In (Accepted invitation)"
                } else {
                    "Active"
                }
            }
            default { "Unknown State: $($guest.ExternalUserState)" }
        }
    }
    
    # Create enhanced guest object
    [PSCustomObject]@{
        UserPrincipalName = $guest.UserPrincipalName
        Mail = $guest.Mail
        ExternalUserState = $guest.ExternalUserState  # Keep for calculations but don't show in reports
        UserStatus = $userStatus
        AccountEnabled = $guest.AccountEnabled
        CreatedDateTime = $guest.CreatedDateTime
        ExternalUserStateChangeDateTime = $guest.ExternalUserStateChangeDateTime
        LastSuccessfulSignIn = $lastSuccessfulSignIn
        LastSignInRequest = $lastSignInRequest
        LastNonInteractiveSignIn = $lastNonInteractiveSignIn
        MostRecentActivity = $mostRecentActivity
        DaysSinceCreation = $daysSinceCreation
        DaysSinceLastActivity = $daysSinceLastActivity
        DaysSinceStateChange = $daysSinceStateChange
        IsInactive = if ($guest.OnPremisesSyncEnabled) { 
            $false  # On-premises synced guests are never marked as inactive
        } elseif ($daysSinceCreation -lt 30) { 
            $false  # Don't mark as inactive if account is less than 30 days old
        } elseif ($mostRecentActivity) { 
            $mostRecentActivity -lt $inactiveCutoffDate 
        } else { 
            $true 
        }
        NeverSignedIn = $mostRecentActivity -eq $null
        OnPremisesSyncEnabled = $guest.OnPremisesSyncEnabled
    }
}

# Sort by most concerning users first (pending, never signed in, then by days since last activity)
$sortedGuests = $processedGuests | Sort-Object @(
    @{Expression = {$_.ExternalUserState -eq "PendingAcceptance"}; Descending = $true},
    @{Expression = {$_.NeverSignedIn}; Descending = $true},
    @{Expression = {$_.DaysSinceLastActivity}; Descending = $true}
)

# Create the export directory if it doesn't exist
if (-not (Test-Path $ExportPath)) {
    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
}

# Generate summary statistics
$stats = @{
    TotalGuests = $guests.Count
    TotalCloudOnlyGuests = ($guests | Where-Object { $_.OnPremisesSyncEnabled -ne $true }).Count
    OnPremisesSyncedGuests = ($guests | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
    PendingAcceptance = ($processedGuests | Where-Object { $_.ExternalUserState -eq "PendingAcceptance" }).Count
    NeverSignedIn = ($processedGuests | Where-Object { $_.NeverSignedIn -and $_.ExternalUserState -eq "Accepted" -and $_.OnPremisesSyncEnabled -ne $true }).Count
    InactiveUsers = ($processedGuests | Where-Object { $_.IsInactive -and $_.ExternalUserState -eq "Accepted" -and -not $_.NeverSignedIn -and $_.OnPremisesSyncEnabled -ne $true }).Count
    ActiveUsers = ($processedGuests | Where-Object { -not $_.IsInactive -and $_.ExternalUserState -eq "Accepted" -and $_.OnPremisesSyncEnabled -ne $true }).Count
    DisabledAccounts = ($processedGuests | Where-Object { -not $_.AccountEnabled }).Count
    LongTermInactive = ($processedGuests | Where-Object { $_.DaysSinceLastActivity -gt 365 -and $_.OnPremisesSyncEnabled -ne $true }).Count
    OldPendingInvitations = ($processedGuests | Where-Object { $_.ExternalUserState -eq "PendingAcceptance" -and $_.DaysSinceCreation -gt 30 }).Count
}

# Determine which reports to generate
$generateCSV = $true
$generateHTML = $true

if ($CSVOnly) {
    $generateHTML = $false
} elseif ($HTMLOnly) {
    $generateCSV = $false
}

# Generate CSV Report
if ($generateCSV) {
    Write-Output "Exporting data to CSV..."
    $sortedGuests | Export-Csv -Path $csvPath -NoTypeInformation -Delimiter ";" -Encoding UTF8
    Write-Output "CSV report exported to: $csvPath"
}

# Generate HTML Report
if ($generateHTML) {
    Write-Output "Generating HTML report..."
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Entra ID Guest Users Report</title>
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
        .controls button { background: #00abeb; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; transition: background 0.3s; font-size: 14px; }
        .controls button:hover { background: #0088cc; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 10px; overflow: hidden; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        td { font-size: 12px; }
        th { background: #f7fafc; font-weight: 600; cursor: pointer; user-select: none; }
        th:hover { background: #edf2f7; }
        tr:hover { background: #f7fafc; }
        .status-pending { background: #fed7d7 !important; color: #c53030; }
        .status-never-signed-in { background: #feebc8 !important; color: #dd6b20; }
        .status-inactive { background: #fefcbf !important; color: #d69e2e; }
        .status-active { background: #c6f6d5 !important; color: #38a169; }
        .status-onprem { background: #e6fffa !important; color: #319795; }
        .account-enabled { color: #38a169; }
        .account-disabled { color: #e53e3e; }
        .footer { margin-top: 30px; padding: 20px; text-align: center; color: #718096; background: white; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Entra ID Guest Users Report</h1>
        <p><strong>Tenant:</strong> $tenantName</p>
        <p><strong>Tenant ID:</strong> $tenantId</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "MMM dd, yyyy HH:mm:ss")</p>
        <p><strong>Inactive Threshold:</strong> $InactiveDays days</p>
        $(if ($PendingAcceptanceOnly) { "<p><strong>Filter:</strong> Pending Acceptance Only</p>" })
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>👥 Total Guest Users</h3>
            <div class="number">$($stats.TotalGuests)</div>
            <div class="subtitle">All guest accounts in tenant</div>
        </div>
        <div class="summary-card">
            <h3>☁️ Cloud-Only Guests</h3>
            <div class="number">$($stats.TotalCloudOnlyGuests)</div>
            <div class="subtitle">Cloud-only guest accounts</div>
        </div>
        <div class="summary-card">
            <h3>🏢 On-Premises Synced</h3>
            <div class="number">$($stats.OnPremisesSyncedGuests)</div>
            <div class="subtitle">Synced from on-premises</div>
        </div>
        <div class="summary-card">
            <h3>⏳ Pending Invitations</h3>
            <div class="number">$($stats.PendingAcceptance)</div>
            <div class="subtitle">Awaiting acceptance</div>
        </div>
        <div class="summary-card">
            <h3>🚫 Never Signed In</h3>
            <div class="number">$($stats.NeverSignedIn)</div>
            <div class="subtitle">Accepted but never used</div>
        </div>
        <div class="summary-card">
            <h3>😴 Inactive Users</h3>
            <div class="number">$($stats.InactiveUsers)</div>
            <div class="subtitle">No recent activity ($InactiveDays+ days)</div>
        </div>
        <div class="summary-card">
            <h3>✅ Active Users</h3>
            <div class="number">$($stats.ActiveUsers)</div>
            <div class="subtitle">Recently active</div>
        </div>
        <div class="summary-card">
            <h3>🔒 Disabled Accounts</h3>
            <div class="number">$($stats.DisabledAccounts)</div>
            <div class="subtitle">Account disabled</div>
        </div>
        <div class="summary-card">
            <h3>🗓️ Long-term Inactive</h3>
            <div class="number">$($stats.LongTermInactive)</div>
            <div class="subtitle">No activity for 1+ year</div>
        </div>
        <div class="summary-card">
            <h3>📅 Old Pending</h3>
            <div class="number">$($stats.OldPendingInvitations)</div>
            <div class="subtitle">Pending for 30+ days</div>
        </div>
    </div>

    <div class="controls">
        <h3>🔍 Search and Filter</h3>
        <input type="text" id="searchInput" placeholder="Search by email or UPN..." onkeyup="filterTable()">
        <select id="statusFilter" onchange="filterTable()">
            <option value="">All User Status</option>
            <option value="Invitation Pending">Invitation Pending</option>
            <option value="Never Signed In (Accepted invitation)">Never Signed In</option>
            <option value="Inactive (Accepted but not used recently)">Inactive</option>
            <option value="Active">Active</option>
            <option value="On-Premises Synced Guest">On-Premises Synced</option>
        </select>
        <select id="stateFilter" onchange="filterTable()">
            <option value="">All External States</option>
            <option value="PendingAcceptance">Pending Acceptance</option>
            <option value="Accepted">Accepted</option>
        </select>
        <select id="accountFilter" onchange="filterTable()">
            <option value="">All Account States</option>
            <option value="enabled">Enabled Accounts</option>
            <option value="disabled">Disabled Accounts</option>
        </select>
        <button onclick="sortTable(4, 'date')">Sort by Created Date</button>
        <button onclick="sortTable(7, 'number')">Sort by Days Since Last Activity</button>
        <button onclick="clearFilters()">Clear All Filters</button>
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'string')">User Principal Name</th>
                <th onclick="sortTable(1, 'string')">Mail</th>
                <th onclick="sortTable(2, 'string')">User Status</th>
                <th onclick="sortTable(3, 'string')">Account Enabled</th>
                <th onclick="sortTable(4, 'date')">Created Date</th>
                <th onclick="sortTable(5, 'date')">State Change Date</th>
                <th onclick="sortTable(6, 'date')">Last Successful Sign In</th>
                <th onclick="sortTable(7, 'number')">Days Since Last Activity</th>
                <th onclick="sortTable(8, 'date')">Most Recent Activity</th>
                <th onclick="sortTable(9, 'number')">Days Since Creation</th>
                <th onclick="sortTable(10, 'string')">Is Inactive</th>
                <th onclick="sortTable(11, 'string')">Never Signed In</th>
                <th onclick="sortTable(12, 'string')">On-Premises Synced</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($guest in $sortedGuests) {
        # Determine status class and row highlighting
        $statusClass = switch -Wildcard ($guest.UserStatus) {
            "Invitation Pending" { "status-pending" }
            "Never Signed In*" { "status-never-signed-in" }
            "Inactive*" { "status-inactive" }
            "Active" { "status-active" }
            "On-Premises Synced Guest" { "status-onprem" }
            default { "" }
        }
        
        $accountClass = if ($guest.AccountEnabled) { "account-enabled" } else { "account-disabled" }
        $accountText = if ($guest.AccountEnabled) { "✅ Enabled" } else { "❌ Disabled" }
        
        # Format dates
        $createdDate = if ($guest.CreatedDateTime) { 
            $guest.CreatedDateTime.ToString("MMM dd, yyyy") 
        } else { 
            "Unknown" 
        }
        
        $stateChangeDate = if ($guest.ExternalUserStateChangeDateTime) { 
            $guest.ExternalUserStateChangeDateTime.ToString("MMM dd, yyyy") 
        } else { 
            "Unknown" 
        }
        
        $lastSuccessfulSignInDate = if ($guest.LastSuccessfulSignIn) { 
            $guest.LastSuccessfulSignIn.ToString("MMM dd, yyyy HH:mm") 
        } else { 
            "Unknown" 
        }
        
        $lastActivityDate = if ($guest.MostRecentActivity) { 
            $guest.MostRecentActivity.ToString("MMM dd, yyyy HH:mm") 
        } else { 
            "Unknown" 
        }
        
        # Handle null values for display
        $daysSinceLastActivityDisplay = if ($guest.DaysSinceLastActivity -ne $null) { 
            $guest.DaysSinceLastActivity 
        } else { 
            "N/A" 
        }
        
        $daysSinceCreationDisplay = if ($guest.DaysSinceCreation -ne $null) { 
            $guest.DaysSinceCreation 
        } else { 
            "N/A" 
        }

        $html += @"
            <tr class="$statusClass" data-status="$($guest.UserStatus)" data-account="$(if ($guest.AccountEnabled) { 'enabled' } else { 'disabled' })">
                <td>$($guest.UserPrincipalName)</td>
                <td>$($guest.Mail)</td>
                <td>$($guest.UserStatus)</td>
                <td class="$accountClass">$accountText</td>
                <td>$createdDate</td>
                <td>$stateChangeDate</td>
                <td>$lastSuccessfulSignInDate</td>
                <td>$daysSinceLastActivityDisplay</td>
                <td>$lastActivityDate</td>
                <td>$daysSinceCreationDisplay</td>
                <td>$(if ($guest.IsInactive) { "‼️ Yes" } else { "✅ No" })</td>
                <td>$(if ($guest.NeverSignedIn) { "‼️ Yes" } else { "✅ No" })</td>
                <td>$(if ($guest.OnPremisesSyncEnabled) { "Yes" } else { "No" })</td>
            </tr>
"@
    }

    $html += @"
        </tbody>
    </table>

    <script>
        function filterTable() {
            const searchInput = document.getElementById('searchInput').value.toLowerCase();
            const statusFilter = document.getElementById('statusFilter').value;
            const accountFilter = document.getElementById('accountFilter').value;
            const table = document.getElementById('reportTable');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const userPrincipalName = row.cells[0].textContent.toLowerCase();
                const mail = row.cells[1].textContent.toLowerCase();
                const status = row.getAttribute('data-status');
                const accountState = row.getAttribute('data-account');
                
                let show = true;
                
                if (searchInput && !userPrincipalName.includes(searchInput) && !mail.includes(searchInput)) show = false;
                if (statusFilter && status !== statusFilter) show = false;
                if (accountFilter && accountState !== accountFilter) show = false;
                
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
                    aVal = parseFloat(aVal.replace(/[^0-9.-]/g, '')) || 0;
                    bVal = parseFloat(bVal.replace(/[^0-9.-]/g, '')) || 0;
                    return bVal - aVal; // Descending for numbers
                } else if (type === 'date') {
                    aVal = new Date(aVal === 'Unknown' || aVal === 'Never' ? '1900-01-01' : aVal);
                    bVal = new Date(bVal === 'Unknown' || bVal === 'Never' ? '1900-01-01' : bVal);
                    return bVal - aVal; // Descending for dates (most recent first)
                }
                
                return aVal.localeCompare(bVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function clearFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('statusFilter').value = '';
            document.getElementById('accountFilter').value = '';
            filterTable();
        }
    </script>

    <div class="footer">
        <p><strong>Legend:</strong></p>
        <p>⏳ <strong>Invitation Pending:</strong> Guest invitation sent but not yet accepted</p>
        <p>🚫 <strong>Never Signed In:</strong> Guest accepted invitation but never actually signed in</p>
        <p>😴 <strong>Inactive:</strong> Guest hasn't signed in within the specified threshold ($InactiveDays days)</p>
        <p>✅ <strong>Active:</strong> Guest has recent sign-in activity</p>
        <p>🏢 <strong>On-Premises Synced Guest:</strong> Guest account synced from on-premises Active Directory</p>
        <br>
        <p>Found this tool helpful? Subscribe to my blog at <a href="https://www.matej.guru" target="_blank" style="color: #00abeb; text-decoration: none;">www.matej.guru</a>.</p>
        <p style="margin-top: 10px; font-size: 0.8em; color: #95a5a6;">This script is provided "as is", without any warranty.</p>
    </div>
</body>
</html>
"@

    # Save the HTML report
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Output "HTML report generated: $htmlPath"
    
    # Open the report in default browser
    Start-Process $htmlPath
}

# Display summary
Write-Output "`n=== GUEST USER REPORT SUMMARY ==="
Write-Output "Report generated on: $(Get-Date -Format 'MMM dd, yyyy HH:mm:ss')"
Write-Output "Tenant: $tenantName"
Write-Output "Inactive threshold: $InactiveDays days"
Write-Output ""
Write-Output "Total guest users: $($stats.TotalGuests)"
Write-Output "├── Cloud-only guests: $($stats.TotalCloudOnlyGuests)"
Write-Output "└── On-premises synced guests: $($stats.OnPremisesSyncedGuests)"
Write-Output ""
Write-Output "Cloud-only guest analysis:"
Write-Output "├── Pending acceptance: $($stats.PendingAcceptance)"
Write-Output "├── Never signed in (accepted): $($stats.NeverSignedIn)"
Write-Output "├── Inactive (>$InactiveDays days): $($stats.InactiveUsers)"
Write-Output "├── Active: $($stats.ActiveUsers)"
Write-Output "└── Disabled accounts: $($stats.DisabledAccounts)"
Write-Output ""
Write-Output "Additional insights:"
Write-Output "├── Long-term inactive (1+ year): $($stats.LongTermInactive)"
Write-Output "└── Old pending invitations (30+ days): $($stats.OldPendingInvitations)"

if ($generateHTML -and $generateCSV) {
    Write-Output ""
    Write-Output "Both reports generated:"
    Write-Output "├── HTML report: $htmlPath"
    Write-Output "└── CSV report: $csvPath"
} elseif ($generateHTML) {
    Write-Output ""
    Write-Output "HTML report generated: $htmlPath"
} elseif ($generateCSV) {
    Write-Output ""
    Write-Output "CSV report generated: $csvPath"
}

# Create a summary file as well
$summaryPath = Join-Path $ExportPath $summaryFileName
@"
=== GUEST USER REPORT SUMMARY ===
Report generated on: $(Get-Date -Format 'MMM dd, yyyy HH:mm:ss')
Tenant: $tenantName
Inactive threshold: $InactiveDays days

Total guest users: $($stats.TotalGuests)
├── Cloud-only guests: $($stats.TotalCloudOnlyGuests)
└── On-premises synced guests: $($stats.OnPremisesSyncedGuests)

Cloud-only guest analysis:
├── Pending acceptance: $($stats.PendingAcceptance)
├── Never signed in (accepted): $($stats.NeverSignedIn)  
├── Inactive (>$InactiveDays days): $($stats.InactiveUsers)
├── Active: $($stats.ActiveUsers)
└── Disabled accounts: $($stats.DisabledAccounts)

Additional insights:
├── Long-term inactive (1+ year): $($stats.LongTermInactive)
└── Old pending invitations (30+ days): $($stats.OldPendingInvitations)

$(if ($generateHTML -and $generateCSV) { "HTML Report: $htmlPath`nCSV Report: $csvPath" } elseif ($generateHTML) { "HTML Report: $htmlPath" } elseif ($generateCSV) { "CSV Report: $csvPath" })
"@ | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Output "Summary also saved to: $summaryPath"
