# Install and connect to Microsoft Graph
# Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All"

# Function to get readable permission names
function Get-ReadablePermissions {
    param(
        [Parameter(Mandatory=$true)]
        $RequiredResourceAccess
    )
    
    $results = @()
    
    foreach ($resource in $RequiredResourceAccess) {
        try {
            # Get the service principal for this resource to get permission names
            $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($resource.ResourceAppId)'" -ErrorAction SilentlyContinue
            
            if ($servicePrincipal) {
                $resourceName = $servicePrincipal.DisplayName
                
                foreach ($permission in $resource.ResourceAccess) {
                    $permissionName = "Unknown"
                    
                    if ($permission.Type -eq "Scope") {
                        # Delegated permission
                        $scope = $servicePrincipal.OAuth2PermissionScopes | Where-Object { $_.Id -eq $permission.Id }
                        if ($scope) {
                            $permissionName = $scope.Value
                        }
                    } elseif ($permission.Type -eq "Role") {
                        # Application permission
                        $role = $servicePrincipal.AppRoles | Where-Object { $_.Id -eq $permission.Id }
                        if ($role) {
                            $permissionName = $role.Value
                        }
                    }
                    
                    $results += [PSCustomObject]@{
                        Resource = $resourceName
                        Permission = $permissionName
                        Type = if ($permission.Type -eq "Scope") { "Delegated" } else { "Application" }
                        PermissionId = $permission.Id
                    }
                }
            } else {
                # Fallback for common resource IDs
                $resourceName = switch ($resource.ResourceAppId) {
                    "00000003-0000-0000-c000-000000000000" { "Microsoft Graph" }
                    "00000002-0000-0000-c000-000000000000" { "Azure Active Directory Graph" }
                    "797f4846-ba00-4fd7-ba43-dac1f8f63013" { "Windows Azure Service Management API" }
                    default { "Unknown Resource ($($resource.ResourceAppId))" }
                }
                
                foreach ($permission in $resource.ResourceAccess) {
                    $results += [PSCustomObject]@{
                        Resource = $resourceName
                        Permission = "Unknown Permission"
                        Type = if ($permission.Type -eq "Scope") { "Delegated" } else { "Application" }
                        PermissionId = $permission.Id
                    }
                }
            }
        } catch {
            Write-Warning "Error processing resource $($resource.ResourceAppId): $($_.Exception.Message)"
        }
    }
    
    return $results
}

# Get all applications
Write-Host "Retrieving all applications from Entra ID..." -ForegroundColor Yellow
$applications = Get-MgApplication -All

Write-Host "Found $($applications.Count) applications. Processing permissions..." -ForegroundColor Green

# Process each application
$allResults = @()
foreach ($app in $applications) {
    Write-Host "Processing: $($app.DisplayName)" -ForegroundColor Cyan
    
    if ($app.RequiredResourceAccess) {
        $permissions = Get-ReadablePermissions -RequiredResourceAccess $app.RequiredResourceAccess
        
        foreach ($permission in $permissions) {
            $allResults += [PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId = $app.AppId
                ObjectId = $app.Id
                ResourceName = $permission.Resource
                PermissionName = $permission.Permission
                PermissionType = $permission.Type
                PermissionId = $permission.PermissionId
            }
        }
    } else {
        # Application has no permissions
        $allResults += [PSCustomObject]@{
            ApplicationName = $app.DisplayName
            ApplicationId = $app.AppId
            ObjectId = $app.Id
            ResourceName = "No permissions configured"
            PermissionName = "None"
            PermissionType = "None"
            PermissionId = "None"
        }
    }
}

# Display results
Write-Host "`nApplications and their permissions:" -ForegroundColor Yellow
$allResults | Format-Table -AutoSize

# Export to CSV
$exportPath = "EntraID_Applications_Permissions.csv"
$allResults | Export-Csv -Path $exportPath -NoTypeInformation
Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green

# Generate HTML Report
$htmlReportPath = "EntraID_Applications_Report.html"

# Calculate statistics
$totalApps = $applications.Count
$appsWithPermissions = ($allResults | Where-Object {$_.PermissionName -ne 'None'} | Select-Object -Unique ApplicationName).Count
$totalPermissions = ($allResults | Where-Object {$_.PermissionName -ne 'None'}).Count
$topPermissions = $allResults | Where-Object {$_.PermissionName -ne 'None'} | 
    Group-Object PermissionName | 
    Sort-Object Count -Descending | 
    Select-Object -First 10 Name, Count

# Group applications by resource
$byResource = $allResults | Where-Object {$_.PermissionName -ne 'None'} | 
    Group-Object ResourceName | 
    Sort-Object Count -Descending

# Create HTML content
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra ID Applications & Permissions Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .header { 
            background: linear-gradient(135deg, #0078d4, #106ebe); 
            color: white; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
        }
        .summary { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-bottom: 20px; 
        }
        .stat-card { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            text-align: center; 
        }
        .stat-number { 
            font-size: 2em; 
            font-weight: bold; 
            color: #0078d4; 
        }
        .section { 
            background: white; 
            margin-bottom: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .section-header { 
            background: #0078d4; 
            color: white; 
            padding: 15px; 
            border-radius: 8px 8px 0 0; 
            font-weight: bold; 
        }
        .section-content { 
            padding: 15px; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 10px; 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }
        th { 
            background-color: #f8f9fa; 
            font-weight: bold; 
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        .permission-type { 
            padding: 3px 8px; 
            border-radius: 4px; 
            font-size: 0.8em; 
            font-weight: bold; 
        }
        .delegated { 
            background-color: #e3f2fd; 
            color: #1976d2; 
        }
        .application { 
            background-color: #f3e5f5; 
            color: #7b1fa2; 
        }
        .searchbox { 
            width: 100%; 
            padding: 8px; 
            margin-bottom: 10px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
        }
        .app-group { 
            margin-bottom: 20px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
        }
        .app-header { 
            background: #f8f9fa; 
            padding: 10px; 
            font-weight: bold; 
            border-bottom: 1px solid #ddd; 
        }
        .app-content { 
            padding: 10px; 
        }
    </style>
    <script>
        function searchTable() {
            var input = document.getElementById("searchInput");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("permissionsTable");
            var rows = table.getElementsByTagName("tr");
            
            for (var i = 1; i < rows.length; i++) {
                var cells = rows[i].getElementsByTagName("td");
                var found = false;
                for (var j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toLowerCase().indexOf(filter) > -1) {
                        found = true;
                        break;
                    }
                }
                rows[i].style.display = found ? "" : "none";
            }
        }
    </script>
</head>
<body>
    <div class="header">
        <h1>Entra ID Applications & Permissions Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <div class="stat-card">
            <div class="stat-number">$totalApps</div>
            <div>Total Applications</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$appsWithPermissions</div>
            <div>Apps with Permissions</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$totalPermissions</div>
            <div>Total Permissions</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">$($byResource.Count)</div>
            <div>Resources Used</div>
        </div>
    </div>
    
    <div class="section">
        <div class="section-header">Top 10 Most Common Permissions</div>
        <div class="section-content">
            <table>
                <tr><th>Permission Name</th><th>Usage Count</th></tr>
"@

# Add top permissions to HTML
foreach ($perm in $topPermissions) {
    $htmlContent += "<tr><td>$($perm.Name)</td><td>$($perm.Count)</td></tr>"
}

$htmlContent += @"
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-header">Permissions by Resource</div>
        <div class="section-content">
            <table>
                <tr><th>Resource Name</th><th>Permission Count</th></tr>
"@

# Add resource summary to HTML
foreach ($resource in $byResource) {
    $htmlContent += "<tr><td>$($resource.Name)</td><td>$($resource.Count)</td></tr>"
}

$htmlContent += @"
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-header">All Applications and Permissions</div>
        <div class="section-content">
            <input type="text" id="searchInput" class="searchbox" placeholder="Search applications, permissions, or resources..." onkeyup="searchTable()">
            <table id="permissionsTable">
                <tr>
                    <th>Application Name</th>
                    <th>Application ID</th>
                    <th>Resource</th>
                    <th>Permission</th>
                    <th>Type</th>
                </tr>
"@

# Add all applications and permissions to HTML
foreach ($result in $allResults) {
    $typeClass = if ($result.PermissionType -eq "Delegated") { "delegated" } else { "application" }
    $htmlContent += @"
                <tr>
                    <td>$($result.ApplicationName)</td>
                    <td><code>$($result.ApplicationId)</code></td>
                    <td>$($result.ResourceName)</td>
                    <td>$($result.PermissionName)</td>
                    <td><span class="permission-type $typeClass">$($result.PermissionType)</span></td>
                </tr>
"@
}

$htmlContent += @"
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-header">Applications Grouped by Name</div>
        <div class="section-content">
"@

# Group applications
$groupedApps = $allResults | Group-Object ApplicationName | Sort-Object Name

foreach ($appGroup in $groupedApps) {
    $htmlContent += @"
            <div class="app-group">
                <div class="app-header">$($appGroup.Name)</div>
                <div class="app-content">
                    <strong>Application ID:</strong> $($appGroup.Group[0].ApplicationId)<br>
                    <strong>Permissions:</strong><br>
"@
    
    $permissions = $appGroup.Group | Where-Object {$_.PermissionName -ne 'None'}
    if ($permissions) {
        foreach ($perm in $permissions) {
            $typeClass = if ($perm.PermissionType -eq "Delegated") { "delegated" } else { "application" }
            $htmlContent += "• $($perm.ResourceName) - $($perm.PermissionName) <span class='permission-type $typeClass'>$($perm.PermissionType)</span><br>"
        }
    } else {
        $htmlContent += "• No permissions configured<br>"
    }
    
    $htmlContent += @"
                </div>
            </div>
"@
}

$htmlContent += @"
        </div>
    </div>
</body>
</html>
"@

# Write HTML file
$htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8
Write-Host "`nHTML report generated: $htmlReportPath" -ForegroundColor Green

# Summary
Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "Total Applications: $totalApps"
Write-Host "Applications with permissions: $appsWithPermissions"
Write-Host "Total permission entries: $totalPermissions"
Write-Host "CSV Export: $exportPath"
Write-Host "HTML Report: $htmlReportPath"