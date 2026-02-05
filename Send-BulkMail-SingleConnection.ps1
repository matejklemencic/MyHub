<#
.SYNOPSIS
    Sends multiple emails using a single persistent SMTP connection.

.PARAMETER MailServer
    The SMTP server hostname or IP address.

.PARAMETER Sender
    The sender email address.

.PARAMETER Recipient
    The recipient email address.

.PARAMETER Subject
    The email subject line.

.PARAMETER Count
    Number of emails to send.

.PARAMETER DelayMs
    Delay in milliseconds between emails. Default 50ms.

.EXAMPLE
    .\Send-BulkMail-SingleConnection.ps1 -MailServer "mail.server.com" -Sender "test@domain.com" -Recipient "user@domain.com" -Subject "Test" -Count 100
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$MailServer,
    
    [Parameter(Mandatory=$true)]
    [string]$Sender,
    
    [Parameter(Mandatory=$true)]
    [string]$Recipient,
    
    [Parameter(Mandatory=$true)]
    [string]$Subject,
    
    [Parameter(Mandatory=$true)]
    [int]$Count,
    
    [Parameter(Mandatory=$false)]
    [int]$DelayMs = 50
)

$successCount = 0
$failureCount = 0

Write-Host "Sending $Count emails from $Sender to $Recipient..." -ForegroundColor Green

try {
    $smtp = New-Object System.Net.Mail.SmtpClient($MailServer, 25)
    $smtp.Timeout = 300000
    
    for ($i = 1; $i -le $Count; $i++) {
        try {
            $message = New-Object System.Net.Mail.MailMessage
            $message.From = $Sender
            $message.To.Add($Recipient)
            $message.Subject = "$Subject - #$i"
            $message.Body = "Email number $i of $Count"
            
            $smtp.Send($message)
            $message.Dispose()
            
            $successCount++
            
            if ($i % 50 -eq 0) {
                Write-Host "Sent: $i" -ForegroundColor Green
            }
            
            Start-Sleep -Milliseconds $DelayMs
        }
        catch {
            $failureCount++
            Write-Host "Failed #$i : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    $smtp.Dispose()
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nComplete: $successCount sent, $failureCount failed" -ForegroundColor Cyan

# Run as Administrator
# [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '0', 'Machine')