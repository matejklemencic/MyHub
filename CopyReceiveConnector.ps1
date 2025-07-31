# Copy Exchange Receive Connector Script
# This script copies all settings from an existing receive connector and creates a new one

param(
    [Parameter(Mandatory=$true)]
    [string]$SourceConnectorName,
    
    [Parameter(Mandatory=$true)]
    [string]$NewConnectorName,
    
    [Parameter(Mandatory=$false)]
    [string]$SourceServer = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$DestinationServer = $null,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Custom","Internet","Internal","Client","Partner")]
    [string]$Usage = $null,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Import Exchange Management Shell if not already loaded
if (!(Get-Command Get-ReceiveConnector -ErrorAction SilentlyContinue)) {
    Write-Host "Loading Exchange Management Shell..." -ForegroundColor Yellow
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
}

try {
    # Get the source receive connector
    Write-Host "Retrieving source connector: $SourceConnectorName" -ForegroundColor Green
    
    if ($SourceServer) {
        $sourceConnector = Get-ReceiveConnector -Identity "$SourceServer\$SourceConnectorName" -ErrorAction Stop
        Write-Host "Source server: $SourceServer" -ForegroundColor Cyan
    } else {
        $sourceConnector = Get-ReceiveConnector -Identity $SourceConnectorName -ErrorAction Stop
    }
    
    Write-Host "Source connector found successfully" -ForegroundColor Green
    
    # Display source connector details
    Write-Host "`nSource Connector Details:" -ForegroundColor Cyan
    Write-Host "Name: $($sourceConnector.Name)"
    Write-Host "Server: $($sourceConnector.Server)"
    Write-Host "Bindings: $($sourceConnector.Bindings -join ', ')"
    Write-Host "Remote IP Ranges: $($sourceConnector.RemoteIPRanges -join ', ')"
    Write-Host "Authentication Mechanisms: $($sourceConnector.AuthMechanism -join ', ')"
    
    # Determine the destination server
    $targetServer = if ($DestinationServer) { 
        Write-Host "Destination server: $DestinationServer" -ForegroundColor Cyan
        $DestinationServer 
    } else { 
        Write-Host "Destination server: $($sourceConnector.Server) (same as source)" -ForegroundColor Cyan
        $sourceConnector.Server 
    }
    
    # Prepare parameters for the new connector
    $newConnectorParams = @{
        Name = $NewConnectorName
        Server = $targetServer
        Bindings = $sourceConnector.Bindings
        RemoteIPRanges = $sourceConnector.RemoteIPRanges
        AuthMechanism = $sourceConnector.AuthMechanism
        PermissionGroups = $sourceConnector.PermissionGroups
        TransportRole = $sourceConnector.TransportRole
    }
    
    # Handle Usage parameter - use provided parameter, source value, or default
    if ($Usage) {
        $newConnectorParams.Usage = $Usage
        Write-Host "Using specified Usage type: $Usage" -ForegroundColor Green
    } elseif ($sourceConnector.Usage -and $sourceConnector.Usage -ne "") {
        $newConnectorParams.Usage = $sourceConnector.Usage
    } else {
        $newConnectorParams.Usage = "Internet"  # Default to Internet instead of Custom
        Write-Host "Warning: Source connector Usage was null, defaulting to 'Internet'" -ForegroundColor Yellow
    }
    
    # Add optional parameters if they exist in source connector (with null checks)
    if ($sourceConnector.Banner) { $newConnectorParams.Banner = $sourceConnector.Banner }
    if ($sourceConnector.ChunkingEnabled -ne $null) { $newConnectorParams.ChunkingEnabled = $sourceConnector.ChunkingEnabled }
    if ($sourceConnector.DeliveryStatusNotificationEnabled -ne $null) { $newConnectorParams.DeliveryStatusNotificationEnabled = $sourceConnector.DeliveryStatusNotificationEnabled }
    if ($sourceConnector.EightBitMimeEnabled -ne $null) { $newConnectorParams.EightBitMimeEnabled = $sourceConnector.EightBitMimeEnabled }
    if ($sourceConnector.BinaryMimeEnabled -ne $null) { $newConnectorParams.BinaryMimeEnabled = $sourceConnector.BinaryMimeEnabled }
    if ($sourceConnector.Fqdn) { $newConnectorParams.Fqdn = $sourceConnector.Fqdn }
    if ($sourceConnector.Comment) { $newConnectorParams.Comment = $sourceConnector.Comment }
    if ($sourceConnector.Enabled -ne $null) { $newConnectorParams.Enabled = $sourceConnector.Enabled }
    if ($sourceConnector.ConnectionTimeout -and $sourceConnector.ConnectionTimeout.ToString() -ne "00:00:00") { $newConnectorParams.ConnectionTimeout = $sourceConnector.ConnectionTimeout }
    if ($sourceConnector.ConnectionInactivityTimeout -and $sourceConnector.ConnectionInactivityTimeout.ToString() -ne "00:00:00") { $newConnectorParams.ConnectionInactivityTimeout = $sourceConnector.ConnectionInactivityTimeout }
    if ($sourceConnector.MessageRateLimit -and $sourceConnector.MessageRateLimit -ne "unlimited") { $newConnectorParams.MessageRateLimit = $sourceConnector.MessageRateLimit }
    if ($sourceConnector.MaxInboundConnection -and $sourceConnector.MaxInboundConnection -ne "unlimited") { $newConnectorParams.MaxInboundConnection = $sourceConnector.MaxInboundConnection }
    if ($sourceConnector.MaxInboundConnectionPerSource -and $sourceConnector.MaxInboundConnectionPerSource -ne "unlimited") { $newConnectorParams.MaxInboundConnectionPerSource = $sourceConnector.MaxInboundConnectionPerSource }
    if ($sourceConnector.MaxInboundConnectionPercentagePerSource -and $sourceConnector.MaxInboundConnectionPercentagePerSource -gt 0) { $newConnectorParams.MaxInboundConnectionPercentagePerSource = $sourceConnector.MaxInboundConnectionPercentagePerSource }
    if ($sourceConnector.MaxHeaderSize -and $sourceConnector.MaxHeaderSize.ToString() -ne "0") { $newConnectorParams.MaxHeaderSize = $sourceConnector.MaxHeaderSize }
    if ($sourceConnector.MaxHopCount -and $sourceConnector.MaxHopCount -gt 0) { $newConnectorParams.MaxHopCount = $sourceConnector.MaxHopCount }
    if ($sourceConnector.MaxLocalHopCount -and $sourceConnector.MaxLocalHopCount -gt 0) { $newConnectorParams.MaxLocalHopCount = $sourceConnector.MaxLocalHopCount }
    if ($sourceConnector.MaxLogonFailures -and $sourceConnector.MaxLogonFailures -gt 0) { $newConnectorParams.MaxLogonFailures = $sourceConnector.MaxLogonFailures }
    if ($sourceConnector.MaxMessageSize -and $sourceConnector.MaxMessageSize.ToString() -ne "0") { $newConnectorParams.MaxMessageSize = $sourceConnector.MaxMessageSize }
    if ($sourceConnector.MaxProtocolErrors -and $sourceConnector.MaxProtocolErrors -ne "unlimited") { $newConnectorParams.MaxProtocolErrors = $sourceConnector.MaxProtocolErrors }
    if ($sourceConnector.MaxRecipientsPerMessage -and $sourceConnector.MaxRecipientsPerMessage -gt 0) { $newConnectorParams.MaxRecipientsPerMessage = $sourceConnector.MaxRecipientsPerMessage }
    if ($sourceConnector.PipeliningEnabled -ne $null) { $newConnectorParams.PipeliningEnabled = $sourceConnector.PipeliningEnabled }
    if ($sourceConnector.ProtocolLoggingLevel -and $sourceConnector.ProtocolLoggingLevel -ne "") { $newConnectorParams.ProtocolLoggingLevel = $sourceConnector.ProtocolLoggingLevel }
    if ($sourceConnector.RequireEHLODomain -ne $null) { $newConnectorParams.RequireEHLODomain = $sourceConnector.RequireEHLODomain }
    if ($sourceConnector.RequireTLS -ne $null) { $newConnectorParams.RequireTLS = $sourceConnector.RequireTLS }
    if ($sourceConnector.EnableAuthGSSAPI -ne $null) { $newConnectorParams.EnableAuthGSSAPI = $sourceConnector.EnableAuthGSSAPI }
    if ($sourceConnector.ExtendedProtectionPolicy -and $sourceConnector.ExtendedProtectionPolicy -ne "") { $newConnectorParams.ExtendedProtectionPolicy = $sourceConnector.ExtendedProtectionPolicy }
    if ($sourceConnector.DomainSecureEnabled -ne $null) { $newConnectorParams.DomainSecureEnabled = $sourceConnector.DomainSecureEnabled }
    if ($sourceConnector.LongAddressesEnabled -ne $null) { $newConnectorParams.LongAddressesEnabled = $sourceConnector.LongAddressesEnabled }
    if ($sourceConnector.OrarEnabled -ne $null) { $newConnectorParams.OrarEnabled = $sourceConnector.OrarEnabled }
    if ($sourceConnector.SuppressXAnonymousTls -ne $null) { $newConnectorParams.SuppressXAnonymousTls = $sourceConnector.SuppressXAnonymousTls }
    if ($sourceConnector.AdvertiseClientSettings -ne $null) { $newConnectorParams.AdvertiseClientSettings = $sourceConnector.AdvertiseClientSettings }
    if ($sourceConnector.ServiceDiscoveryFqdn) { $newConnectorParams.ServiceDiscoveryFqdn = $sourceConnector.ServiceDiscoveryFqdn }
    if ($sourceConnector.TlsCertificateName) { $newConnectorParams.TlsCertificateName = $sourceConnector.TlsCertificateName }
    if ($sourceConnector.TlsDomainCapabilities) { $newConnectorParams.TlsDomainCapabilities = $sourceConnector.TlsDomainCapabilities }
    
    # Display all parameters that will be used for the new connector
    Write-Host "`n==================== NEW CONNECTOR CONFIGURATION ====================" -ForegroundColor Cyan
    Write-Host "The following settings will be applied to the new connector:" -ForegroundColor White
    Write-Host ""
    
    # Display core parameters
    Write-Host "CORE SETTINGS:" -ForegroundColor Yellow
    Write-Host "  Name: $($newConnectorParams.Name)" -ForegroundColor White
    Write-Host "  Server: $($newConnectorParams.Server)" -ForegroundColor White
    Write-Host "  Bindings: $($newConnectorParams.Bindings -join ', ')" -ForegroundColor White
    Write-Host "  Remote IP Ranges: $($newConnectorParams.RemoteIPRanges -join ', ')" -ForegroundColor White
    Write-Host "  Authentication Mechanism: $($newConnectorParams.AuthMechanism -join ', ')" -ForegroundColor White
    Write-Host "  Permission Groups: $($newConnectorParams.PermissionGroups -join ', ')" -ForegroundColor White
    Write-Host "  Transport Role: $($newConnectorParams.TransportRole)" -ForegroundColor White
    Write-Host "  Usage: $($newConnectorParams.Usage)" -ForegroundColor White
    
    # Display optional parameters if they exist
    if ($newConnectorParams.Count -gt 8) {  # More than the core 8 parameters
        Write-Host "`nADDITIONAL SETTINGS:" -ForegroundColor Yellow
        foreach ($param in $newConnectorParams.GetEnumerator()) {
            if ($param.Key -notin @('Name','Server','Bindings','RemoteIPRanges','AuthMechanism','PermissionGroups','TransportRole','Usage')) {
                Write-Host "  $($param.Key): $($param.Value)" -ForegroundColor White
            }
        }
    }
    
    Write-Host "`n=====================================================================" -ForegroundColor Cyan
    
    # Ask for confirmation unless -Force switch is used
    if (-not $Force) {
        Write-Host ""
        $confirmation = Read-Host "Do you want to create the new receive connector with these settings? (Y/N)"
        
        if ($confirmation -notmatch '^[Yy]') {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            return
        }
    }
    
    # Create the new receive connector
    Write-Host "`nCreating new receive connector: $NewConnectorName on server: $targetServer" -ForegroundColor Green
    $newConnector = New-ReceiveConnector @newConnectorParams
    
    Write-Host "New receive connector created successfully!" -ForegroundColor Green
    
    # Display new connector details
    Write-Host "`nNew Connector Details:" -ForegroundColor Cyan
    Write-Host "Name: $($newConnector.Name)"
    Write-Host "Server: $($newConnector.Server)"
    Write-Host "Bindings: $($newConnector.Bindings -join ', ')"
    Write-Host "Remote IP Ranges: $($newConnector.RemoteIPRanges -join ', ')"
    Write-Host "Authentication Mechanisms: $($newConnector.AuthMechanism -join ', ')"
    
    Write-Host "`nReceive connector copied successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Error occurred: $($_.Exception.Message)"
    Write-Host "Please ensure:" -ForegroundColor Yellow
    Write-Host "1. Exchange Management Shell is available" -ForegroundColor Yellow
    Write-Host "2. You have sufficient permissions to create receive connectors" -ForegroundColor Yellow
    Write-Host "3. The source connector name is correct" -ForegroundColor Yellow
    Write-Host "4. The new connector name doesn't already exist" -ForegroundColor Yellow
}

# Example usage:
# Copy from same server (original functionality):
# .\CopyReceiveConnector.ps1 -SourceConnectorName "Default Frontend MAIL01" -NewConnectorName "Custom Frontend MAIL01"

# Copy from a specific source server to the same server:
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -SourceServer "MAIL01"

# Copy from one server to a different server:
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -SourceServer "MAIL01" -DestinationServer "MAIL02"

# Copy from current server to a different server:
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -DestinationServer "MAIL02"

# Skip confirmation prompt (auto-create):
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -Force

# Specify a different Usage type:
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -Usage "Internet"

# Combined example with cross-server copy and specific usage:
# .\CopyReceiveConnector.ps1 -SourceConnectorName "MyConnector" -NewConnectorName "MyConnector-Copy" -SourceServer "MAIL01" -DestinationServer "MAIL02" -Usage "Client" -Force
