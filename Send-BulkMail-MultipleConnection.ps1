<#
.SYNOPSIS
    Sends multiple emails through an Exchange server on port 25 without authentication.

.DESCRIPTION
    This script sends a specified number of emails to an Exchange server using SMTP on port 25.
    No authentication is required.

.PARAMETER MailServer
    The Exchange server hostname or IP address.

.PARAMETER Sender
    The email address of the sender.

.PARAMETER Recipient
    The email address of the recipient.

.PARAMETER Subject
    The subject line of the email.

.PARAMETER Count
    The number of emails to send.

.PARAMETER Body
    The body text of the email. Default is "Test email message".

.EXAMPLE
    .\Send-BulkMail-MultipleConnection.ps1 -MailServer "mail.example.com" -Sender "sender@example.com" -Recipient "recipient@example.com" -Subject "Test Email" -Count 10
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
    [string]$Body = "Test email message"
)

$successCount = 0
$failureCount = 0

Write-Host "Starting to send $Count emails..." -ForegroundColor Green
Write-Host "Mail Server: $MailServer"
Write-Host "From: $Sender"
Write-Host "To: $Recipient"
Write-Host "Subject: $Subject"
Write-Host ""

for ($i = 1; $i -le $Count; $i++) {
    try {
        Send-MailMessage -SmtpServer $MailServer `
                        -Port 25 `
                        -From $Sender `
                        -To $Recipient `
                        -Subject "$Subject - Email #$i" `
                        -Body "$Body`n`nEmail number: $i of $Count" `
                        -ErrorAction Stop
        
        $successCount++
        Write-Host "Email #$i sent successfully" -ForegroundColor Green
    }
    catch {
        $failureCount++
        Write-Host "Failed to send email #$i : $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Small delay to avoid overwhelming the server
    # Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "Total emails attempted: $Count"
Write-Host "Successfully sent: $successCount" -ForegroundColor Green
Write-Host "Failed: $failureCount" -ForegroundColor Red