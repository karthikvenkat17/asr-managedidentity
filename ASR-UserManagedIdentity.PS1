<#
.SYNOPSIS
   Used to assign user managed identity to VMs replicated using ASR. 
.DESCRIPTION
    This runbook can be used as a post step in the ASR recovery plan to assign user managed identity to VMs as part of ASR failover process. 
    It is assumed that User Managed identities are common for group of ASR VMs. For example VMs in Group 1 needs be assigned identity1.
    Runbook requires minimum of 2 variables added to the automation account
    Variable 1 -  ASR group ID
    Value 1 -  User assigned Identity to be assigned to the group id <variable1>
    Variable 2 - <GroupID>-rg 
    Value 2 -  Resource group of the user managed identity
    Multiple sets of above variable can be used if multiple ASR groups are used.
.PARAMETER RecoveryPlanContext
    Recovery plan context passed by ASR. https://docs.microsoft.com/en-us/azure/site-recovery/site-recovery-runbook-automation
    If testing the runbook from test pane of Azure portal uncomment line 109
.NOTES
    Author: Karthik Venkatraman
#>

param (
    [Parameter(Mandatory=$true)]
    [Object]$RecoveryPlanContext
)

function Get-TimeStamp {    
    return "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

function Set-VMManagedIdentity {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory= $true)]
            [ValidateNotNullOrEmpty()]
            [string]$VMName,
            [Parameter(Mandatory= $true)]
            [ValidateNotNullOrEmpty()]
            [string]$rgName,
            [Parameter(Mandatory= $true)]
            [ValidateNotNullOrEmpty()]
            [string]$failOverGroup
        )
        begin {}
        process {
            try {
                $managedID = Get-AutomationVariable -Name $failOverGroup
                $managedIDResourceGroup = Get-AutomationVariable -Name ($managedID + "-rg")
                $managedIDConfig = Get-AzUserAssignedIdentity -name $managedID -ResourceGroupName $managedIDResourceGroup
                $vmConfig = Get-AzVM -ResourceGroupName $rgName -Name $VMName
                $output = Update-AzVM -ResourceGroupName $rgName -VM $vmConfig -IdentityType UserAssigned -IdentityId $managedIDConfig.id
                    if ($output.IsSuccessStatusCode -eq "True" -And $output.StatusCode -eq "OK") {
                        $result = [PSCustomObject]@{
                        VirtualMachine = $VMName;
                        UserManagedIdentity = $managedID;
                        AssignmentStatus = "Success";
                        ReasonPhrase = $output.ReasonPhrase
                        }
                    }
                else {
                    $result += [PSCustomObject]@{
                        VirtualMachine = $VMName;
                        UserManagedIdentity = $managedID;
                        AssignmentStatus = "Failed";
                        ReasonPhrase = $output.ReasonPhrase
                        }
                }
            return $result
            }
            catch {
                Write-Output  $_.Exception.Message
                Write-Output "$(Get-TimeStamp) Managed Identity could not be assigned" 
                exit 1
            }
        }
        end {}
    }


##Main Program##

try {
    Set-PSDebug -Trace 2
    # Ensures you do not inherit an AzContext in your runbook
    Disable-AzContextAutosave -Scope Process
    # Connect to Azure with system-assigned managed identity
    $AzureContext = (Connect-AzAccount -Identity).context
    Write-Output $AzureContext
    # set and store context
    $AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
    if (!$AzureContext) {
        Write-Error "Context could not be obtained. Check if System assigned managed identity is enabled"
    }
    else {
        Write-Output "Working on subscription $($AzureContext.Subscription) and tenant $($AzureContext.Tenant)"
    }
    #Enable below if testing from test pane in Azure Portal
    #$RecoveryPlanContext = ConvertFrom-Json -InputObject $RecoveryPlanContext
    $VMinfo = $RecoveryPlanContext.VmMap | Get-Member | Where-Object MemberType -EQ NoteProperty | Select-Object -ExpandProperty Name
    $vmMap = $RecoveryPlanContext.VmMap
    foreach($VMID in $VMinfo)
        {
            $VM = $vmMap.$VMID                
                if( !(($Null -eq $VM) -Or ($Null -eq $VM.ResourceGroupName) -Or ($Null -eq $VM.RoleName))) {
                #this check is to ensure that we skip when some data is not available else it will fail
                Write-output "Resource group name - $VM.ResourceGroupName"
                Write-output "VMName - $VM.RoleName"
                $result = Set-VMManagedIdentity -VMName $VM.RoleName -rgName $VM.ResourceGroupName `
                                                  -failOverGroup $RecoveryPlanContext.GroupId
                Write-Output $(Get-TimeStamp) 
                Write-Output $result
                }
         }
}
catch {
    Write-Output  $_.Exception.Message
    Write-Output "Runbook to assign managed identity failed"
}
