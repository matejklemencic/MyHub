param(
    # Mandatory TenantId for connecting to Entra.
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    # If set, only export guests with an externalUserState of "PendingAcceptance"
    [switch]$PendingAcceptanceOnly
)

# Connect to Entra ID (Azure AD) with the required scope using the provided TenantId.
Connect-Entra -Scopes 'User.Read.All' -TenantId $TenantId

# Retrieve all guest users from Entra ID (Azure AD).
$guests = Get-EntraUser -Filter "userType eq 'Guest'" -All -Property DisplayName, UserPrincipalName, createdDateTime, signInActivity, externalUserState, DirSyncEnabled

# Exclude guests that are DirSyncEnabled.
$guests = $guests | Where-Object { $_.DirSyncEnabled -ne $true }

# If the PendingAcceptanceOnly switch is set, filter to only include guests with a PendingAcceptance state.
if ($PendingAcceptanceOnly) {
    $guests = $guests | Where-Object { $_.externalUserState -eq "PendingAcceptance" }
}

# Get the current date formatted as YYYYMMDD.
$exportDate = Get-Date -Format "yyyyMMdd"

# Retrieve the tenant's display name.
$tenantName = (Get-EntraTenantDetail).DisplayName

# Build the CSV file path using the tenant name and the current date.
$csvPath = "C:\temp\$tenantName" + "_Guests_Report_" + "$exportDate.csv"

# Export the guest users' details to a CSV file.
# Only select relevant properties and create a calculated field for the last successful sign-in.
$guests |
    Select-Object UserPrincipalName,
                  externalUserState,
                  createdDateTime,
                  @{Name = 'LastSuccessfulSignIn'; Expression = { $_.signInActivity.lastSuccessfulSignInDateTime }} |
    Sort-Object -Property LastSuccessfulSignIn -Descending |
    Export-Csv -Path $csvPath -NoTypeInformation -Delimiter ";"

# Output the file path for confirmation.
Write-Output "Report exported to: $csvPath"

