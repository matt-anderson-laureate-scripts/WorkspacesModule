<#

        Module for Managing Workspaces
        Requirements:
            AWSPowerShell Module
            Windows powerrshell 5+:
                        CredentialManager Module
            PowerShell Core 6+ (mac)
                        Utilizes the Local Keychain for AWS cred store
            API Access into AWS
#>


Import-Module AWSPowerShell

#Global Vars

$global:DefaultRegion = "us-east-1"
$global:DefaultDir = "d-90671e57c0"
$Global:StoreAs = "AWSCreds"
$Global:SessionArgs = $null



Function Initialize-AWSPSSession {

    param (
       [string]$mfatoken
    )

    Write-host "Initializing SessionTokens with AWS...."
if($PSVersiontable.psedition -like "*core*"){
    $AccessKey = security find-internet-password -a AWSAccessKey -w
    $SecretKey = security find-internet-password -a AWSSecretKey -w
    $AssumedRole = security find-internet-password -a AWSAssumedRole -w
    $MfaSerial = security find-internet-password -a AWSMfaSerial -w
} else {
    $AccessKey = (Get-storedcredential -target AWSAccessKey).GetNetworkCredential().password
    $SecretKey = (Get-storedcredential -target AWSSecretKey).GetNetworkCredential().password
    $AssumedRole = (Get-storedcredential -target AWSAssumedRole).GetNetworkCredential().password
$MfaSerial = (Get-storedcredential -target AWSMfaSerial).GetNetworkCredential().password
}




    if( $AccessKey -ne $Null -and
        $SecretKey -ne $null -and
        $AssumedRole -ne $null -and
        $MfaSerial -ne $Null
        ) {
            Initialize-AWSDefaultConfiguration -Region $DefaultRegion -MfaSerial $MFASERIAL -RoleArn $AssumedRole -SourceProfile $StoreAs -scope Global
            if($PSVersiontable.psedition -like "*core*"){
                Set-AWSCredential -AccessKey $AccessKey -SecretAccessKey $SecretKey -storeas $Global:StoreAs
                
            } else {
                #set Initial Creds
                Set-AWSCredential -AccessKey $AccessKey -SecretAccessKey $SecretKey  -scope Global

            }
           
        
            #$ST = get-stssessiontoken
            
        #Start MFA
        #get-wksworkspace -Region $DefaultRegion
        if($mfatoken){
            $Global:SessionArgs = use-stsrole  -SerialNumber $MfaSerial -rolesessionname "AssumedRole"  -RoleArn $AssumedRole -tokencode $mfatoken -AccessKey $AccessKey -SecretAccessKey $SecretKey
        } else {
            $Workspaces = get-wksworkspace
        }
        
        #Assume Role
        
        

        
        

        Write-host "Connection Complete."
        
        #$ST

    } else {

        Write-host "Error: AWS Credentials not in Credential Store." -ForegroundColor Yellow
        Write-host "Please used the Add-AWSCredentials to add your Access, secret, AssumedRole and MfASerial, and then re-import the WorkspacesModule"

    }
}

Function Add-AWSCredentials {

    #Function to add your AWS Credentials to the Windows store
    $AK = read-host -Prompt "Please enter Access Key :"
    $SK = read-host -Prompt "Please enter Secret Key :"
    $AR = read-host -Prompt "Please enter AssumedRole (arn) :"
    $MfaS = read-host -Prompt "Please enter Mfa Serial :"

    if($PSVersionTable.psEdition -like "*core*"){
        security add-internet-password -a AWSAssumedRole -s AWSAssumedRole -w $AR
        security add-internet-password -a AWSAccessKey -s AWSAccessKey -w  $AK
        security add-internet-password -a AWSSecretKey -s AWSSecretKey -w $SK
        security add-internet-password -a AWSMfaSerial -s AWSMfaSerial -w $MfaS
        
    } else {
        New-StoredCredential -target AWSAccessKey -password $AK
        New-StoredCredential -target AWSSecretKey -password $SK
        New-StoredCredential -target AWSAssumedRole -password $AR
        New-StoredCredential -target AWSMfaSerial -password $MfaS
    }

    
}

Function New-LOEWorkspaces {

    param(
        [string]$CSVFile,
        [string]$DirID = $global:DefaultDir,
        [string]$EncKey = "alias/laureate/EBS",
        [switch]$ExportResults,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs
    )

    

    $WorkspaceCreationStatus = New-Object System.Collections.ArrayList

    if(!(Test-Path $CSVFile)){

        Write-host "CSV file could not be found!" -ForegroundColor Red

    } else {

        

        #Import CSV
        $WorkspaceUsers = import-csv $CSVFile

        #Get Bundles
        if($UseSessionToken){
            $WorkspaceBundles = get-wksworkspaceBundle -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
        } else {
            $WorkspaceBundles = get-wksworkspaceBundle
        }
        foreach ($User in $WorkspaceUsers){
            
            #Verify Valid Bundle from CSV
            $BundleID = ($WorkspaceBundles | ?{$_.name -eq $user.Bundle}).bundleid

            if($BundleID){

                #Create Cuscom Workspace Object
                $Response = $Null

                $WorkSpaceProps = new-object Amazon.WorkSpaces.Model.WorkspaceProperties

                $WorkspaceProps.ComputeTypeName = $User.ComputeTypeName
                $WorkspaceProps.RootVolumeSizeGib = $User.RootVolumeSizeGib
                $WorkspaceProps.RunningMode = $User.RunningMode
                
                $WorkspaceProps.UserVolumeSizeGib = $User.UserVolumeSizeGib

                if($User.RunningMode -eq "AUTO_STOP"){
                    $WorkspaceProps.RunningModeAutoStopTimeoutInMinutes = $User.RunningModeAutoStopTimeoutInMinutes
                }
                

                $TempWorkspaceObj = @{
                    "BundleID" = $BundleID;
                    "DirectoryId" = $DirID;
                    "UserName" = $User.Username;
                    "Tags" = $Tags
                    "RootVolumeEncryptionEnabled" = $True;
                    "UserVolumeEncryptionEnabled" = $True;
                    "VolumeEncryptionKey" = $EncKey;
                    "WorkspaceProperties" = $WorkSpaceProps
                }

                #Create Workspace

                if($UseSessionToken){
                    $Response = New-WksWorkspace -workspace $TempWorkspaceObj -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                 } else {
                    $Response = New-WksWorkspace -workspace $TempWorkspaceObj 
                    }
                

                if($response.FailedRequests) {

                    $CurrObj = [pscustomobject]@{"Username"=$User.username;"WorkspaceID"="N/A";"Status"="Failed";"Error"=$Response.FailedRequests.ErrorMessage}
                    $WorkspaceCreationStatus.add($CurrObj) | Out-Null
                    $CurrObj

                } else {

                    if($User.tags){

                        $TagArray = $User.Tags -split(";")

                        foreach ($UserTag in $TagArray){

                            $NewTag = New-Object Amazon.WorkSpaces.Model.Tag
                            $NewTag.key = ($UserTag -split("="))[0]
                            $NewTag.value = ($UserTag -split("="))[1]
                            if($UseSessionToken){
                            New-WKSTag -workspaceid $Response.PendingRequests.WorkspaceID -Tag $NewTag -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                            } else {
                                New-WKSTag -workspaceid $Response.PendingRequests.WorkspaceID -Tag $NewTag 
                            }
                        }
                    }

                        $CurrObj = [pscustomobject]@{"Username"=$User.username;"WorkspaceID"=$Response.PendingRequests.WorkspaceID;"Status"="Success";"Error"="N/A"}
                    $WorkspaceCreationStatus.add($CurrObj) | Out-Null
                    $CurrObj
                    
                }
                
            } else {

                $CurrObj = [pscustomobject]@{"Username"=$User.username;"WorkspaceID"="N/A";"Status"="Failed";"Error"="Invalid BundleID"}
                $WorkspaceCreationStatus.add($CurrObj) | Out-Null
                $CurrObj

            }
            
        }

        if($ExportResults){

            $ExportDate = get-date -Format MM_dd_yyyy-HH_mm_ss
            $OutputFile = ".\WorkspaceResults-$ExportDate.csv"
            $WorkspaceCreationStatus | export-csv $OutputFile -NoTypeInformation
            Write-host "Please refer to $OutputFile for results"

        }
    }

}

Function Redo-LOEWorkspaces {
    param(
        [Parameter(Mandatory,ParameterSetName = 'Individual')]
        [string]$Username,
        [Parameter(ParameterSetName = 'Individual')]
        [string]$DirectoryID = $global:DefaultDir,
        [Parameter(Mandatory,ParameterSetName = 'FullBundle')]
        [string]$BundleName,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs

    )
    

    if($Username){

        #If only an individual is being rebuilt
        if($UseSessionToken){
            $ValidUser = get-wksworkspace -username $Username -DirectoryID $DirectoryID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
         } else {
            $ValidUser = get-wksworkspace -username $Username -DirectoryID $DirectoryID
            }
        

        if($ValidUser){

            if($UseSessionToken){
                $Result = reset-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
             } else {
                $Result = reset-wksworkspace -workspaceID $ValidUser.WorkspaceID
                }

            if(!$Result){

                #Rebuild request sent successfully
                [pscustomobject]@{"Username"="$($ValidUser.Username)";"WorkspaceID"="$($ValidUser.WorkspaceID)";"RebuildRequest"="Sent";"Error"="N/A";}

            } else {

                #Rebuild request failed
                $RebuildError = $Result.ErrorMessage
                [pscustomobject]@{"Username"="$($ValidUser.Username)";"WorkspaceID"="$($ValidUser.WorkspaceID)";"RebuildRequest"="Failed";"Error"="$RebuildError";}
              
            }
            
        } else {
            Write-host "Could not find a workspace for user $Username in directory $DirectoryID" -ForegroundColor Red
        }

    } 

    if($BundleName){
        if($UseSessionToken){
            $Bundles = get-wksworkspaceBundle -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
         } else {
            $Bundles = get-wksworkspaceBundle
            }

        $ValidBundle = $Bundles | ?{$_.Name -eq $BundleName}

        if($ValidBundle){
            
            #Build Choice for Confirmation of rebuilds
            $Yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Confirm: Yes'
            $No = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Confirm: No'
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)


            if($UseSessionToken){
                $WorkspacesInBundle = get-wksworkspace -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken | ? { $_.BundleID -eq $ValidBundle.BundleID}
             } else {
                $WorkspacesInBundle = get-wksworkspace | ? { $_.BundleID -eq $ValidBundle.BundleID}
                }
            
            $WorkspaceCount = $WorkspacesInBundle.count
            Write-host "Warning: There are $WorkspaceCount Workspace(s) associated with Bundle $BundleName" -ForegroundColor Yellow
            Write-host "Please confirm to rebuild ALL Workspaces!" -ForegroundColor Yellow
            
            $result = $host.ui.PromptForChoice($null, $null, $options, 1)
            if($result -eq 0){
                Write-host "Beginning Rebuild Requests..."
                foreach ($LOEWorkspace in $WorkspacesInBundle){

                    
                    #Write-host " - Sending request for Workspace $($LOEWorkspace.WorkspaceID) (User: $($LOEWorkspace.Username)):`t" -NoNewline
                    if($UseSessionToken){
                        $Result = reset-wksworkspace -workspaceID $LOEWorkspace.workspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                     } else {
                        $Result = reset-wksworkspace -workspaceID $LOEWorkspace.workspaceID

                        }
                    
                    if(!$Result){

                        #Rebuild request sent successfully
                        [pscustomobject]@{"Username"="$($LOEWorkspace.Username)";"WorkspaceID"="$($LOEWorkspace.WorkspaceID)";"RebuildRequest"="Sent";"Error"="N/A";}

                    } else {

                        #Rebuild request failed
                        $RebuildError = $Result.ErrorMessage
                        [pscustomobject]@{"Username"="$($LOEWorkspace.Username)";"WorkspaceID"="$($LOEWorkspace.WorkspaceID)";"RebuildRequest"="Failed";"Error"="$RebuildError";}
                      
                    }
                    
                }

            } elseif ($Result -eq 1){

                Write-host "Cancelled rebuild request" -ForegroundColor Yellow

            }

        } else {
            Write-host "Could not find a Bundle with the name $BundleName" -ForegroundColor Red
        }

    }



}

Function Restart-LOEWorkspaces {
    param(
        [Parameter(Mandatory,ParameterSetName = 'Individual')]
        [string]$Username,
        [Parameter(ParameterSetName = 'Individual')]
        [string]$DirectoryID = $global:DefaultDir,
        [switch]$MonitorStatus,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs

    )
    if($UseSessionToken){
        $ValidUser = get-wksworkspace -username $Username -DirectoryID $DirectoryID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
     } else {
        $ValidUser = get-wksworkspace -username $Username -DirectoryID $DirectoryID

        }
    

    if($ValidUser){
        if($UseSessionToken){
            $Result = restart-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
         } else {
            $Result = restart-wksworkspace -workspaceID $ValidUser.WorkspaceID
    
            }
        

        if(!$Result){

            #Rebuild request sent successfully
            if($MonitorStatus){ 
                if($UseSessionToken){
                    get-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                    Write-host "Request successfully sent..."
                    $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken).state
                    Write-host "Current Status: " -nonewline
                    Write-host "$WKSStatus" -ForegroundColor green
                    While($WKSStatus -eq "AVAILABLE"){
                        start-sleep 10
                        $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken).state
                        
                    }
                    Write-host "Current Status: " -nonewline
                    Write-host "$WKSStatus" -ForegroundColor green
                    While($WKSStatus -eq "REBOOTING" -or $WKSStatus -eq "PENDING"){
                        start-sleep 10
                        $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken).state
                        
                    }
                    if($WKSStatus -eq "AVAILABLE"){
                        Write-host "Reboot complete!"
                    } elseif ($WKSStatus -eq "ERROR") {
                        Write-host "Error: Reboot could not complete - please check the workspace" -ForegroundColor Red
                    } else {
                        Write-host "Final Status: " -nonewline
                        Write-host "$WKSStatus" -ForegroundColor Yellow
                    }

                }else {
                    Write-host "Request successfully sent..."
                    $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID).state
                    Write-host "Current Status: " -nonewline
                    Write-host "$WKSStatus" -ForegroundColor green
                    While($WKSStatus -eq "AVAILABLE"){
                        start-sleep 10
                        $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID).state
                        
                    }
                    Write-host "Current Status: " -nonewline
                    Write-host "$WKSStatus" -ForegroundColor green
                    While($WKSStatus -eq "REBOOTING" -or $WKSStatus -eq "PENDING"){
                        start-sleep 10
                        $WKSStatus = (get-wksworkspace -workspaceID $ValidUser.WorkspaceID).state
                        
                    }
                    if($WKSStatus -eq "AVAILABLE"){
                        Write-host "Reboot complete!"
                    } elseif ($WKSStatus -eq "ERROR") {
                        Write-host "Error: Reboot could not complete - please check the workspace" -ForegroundColor Red
                    } else {
                        Write-host "Final Status: " -nonewline
                        Write-host "$WKSStatus" -ForegroundColor Yellow
                    }
                




            

             } else {
                $Result = restart-wksworkspace -workspaceID $ValidUser.WorkspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                
                }
                


                
                
            } else {
                [pscustomobject]@{"Username"="$($ValidUser.Username)";"WorkspaceID"="$($ValidUser.WorkspaceID)";"RestartRequest"="Sent";"Error"="N/A";}
            }
        } else {

            #Rebuild request failed
            $RebuildError = $Result.ErrorMessage
            [pscustomobject]@{"Username"="$($ValidUser.Username)";"WorkspaceID"="$($ValidUser.WorkspaceID)";"RestartRequest"="Failed";"Error"="$RebuildError";}
          
        }
        
    } else {
        Write-host "Could not find a workspace for user $Username in directory $DirectoryID" -ForegroundColor Red
    }

}

Function Get-LOEWorkspaceConnectionStatus {
    param(
        [string]$username,
        [string]$DirectoryID = $global:DefaultDir,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs
    )
    if($UseSessionToken){
        $Bundles = get-wksworkspaceBundle -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
     } else {
        $Bundles = get-wksworkspaceBundle

    }
    
    
    if($Username){
        #Single User
        if($UseSessionToken){
            $WksResults = get-wksworkspace -username $username -DirectoryID $DirectoryID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
         } else {
            $WksResults = get-wksworkspace -username $username -DirectoryID $DirectoryID
    
            }
        
        if($WksResults){
            if($UseSessionToken){
                $AllConnStatus = Get-WKSWorkspacesConnectionStatus -workspaceID $WksResults.workspaceID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
             } else {
                $AllConnStatus = Get-WKSWorkspacesConnectionStatus -workspaceID $WksResults.workspaceID
        
                }
             
        } else {
            Write-host "Not a valid User"
            [pscustomobject]@{
                "Username"="$Username"
                "ConnectionStatus"="Not a valid User"
                "WorkspaceID"="Not a valid User"
                "ComputerName"="Not a valid User"
                "LastConnectionTime"="Not a valid User"
                "Bundle"="Not a valid User"
                "RootStorage"="Not a valid User"
                "UserStorage"="Not a valid User"
                "ComputeType"="Not a Valid User"
            }
        }

    } else {
        #All Workspaces
        #Write-progress -Activity "Getting All Workspaces Connection Info" -CurrentOperation "Gathering Workspaces Status"
        if($UseSessionToken){
            $WksResults = get-wksworkspace -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
            $AllConnStatus = Get-WKSWorkspacesConnectionStatus -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
        } else {
            $WksResults = get-wksworkspace
            $AllConnStatus = Get-WKSWorkspacesConnectionStatus
    
            }
        
        #Write-progress -Activity "Getting All Workspaces Connection Info" -CurrentOperation "Gathering Connections Status"
        
        
    }
$TotalWorkspaces = $WksResults.count
$i = 0
    foreach($Workspace in $WksResults){
       $i++
       [int32]$PercComplete = ($i/$TotalWorkspaces)*100
        #Write-progress -Activity "Getting All Workspaces Connection Info" -CurrentOperation "Returning info for User: $($Workspace.Username) - Computer: $($Workspace.Computername)" -PercentComplete $PercComplete
        $UserConnStatus = $AllConnStatus | ?{$_.workspaceID -eq $Workspace.WorkspaceID}
        $CurrBundle = $Bundles | ?{$_.bundleid -eq $Workspace.bundleID}
        $RS = $CurrBundle.RootStorage.capacity
        $US = $CurrBundle.UserStorage.capacity
        
        $CurrUser = [pscustomobject]@{
            "Username"="$($Workspace.username)"
            "ConnectionStatus"="$($UserConnStatus.ConnectionState)"
            "WorkspaceID"="$($Workspace.WorkspaceID)"
            "ComputerName"="$($Workspace.Computername)"
            "LastConnectionTime"=""
            "Bundle"="$($CurrBundle.Name)"
            "RootStorage"="$RS GB"
            "UserStorage"="$US GB"
            "ComputeType"="$($CurrBundle.ComputeType.Name)"
        }
        if($UserConnStatus.LastKnownUserConnectionTimestamp.tostring() -eq "1/1/01 12:00:00 AM"){
            $CurrUser.LastConnectionTime = "Never"
            
        } else {
            $CurrUser.LastConnectionTime = $UserConnStatus.LastKnownUserConnectionTimestamp.tostring()
        }
        $CurrUser

    }

}

Function Get-LOEWorkspacesStatus {
    param(
        [string]$DirectoryID = $global:DefaultDir,
        [string]$Region = $global:DefaultRegion,
        [switch]$Readable,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs
    )

    Write-Verbose "Gathering Workspaces..."
    if($UseSessionToken){
        $AllWorkspaces = get-wksworkspace -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
        
    } else {
        $AllWorkspaces = get-wksworkspace

        }
    
    Write-Verbose "Getting Connection Status..."
    if($UseSessionToken){
        $AllworkspaceConnStatus = Get-LOEWorkspaceConnectionStatus -UseSessionToken
        
    } else {
        $AllworkspaceConnStatus = Get-LOEWorkspaceConnectionStatus

        }
    
    $Connected = $AllWorkspaceConnStatus | ?{$_.ConnectionStatus -eq "Connected"}
    $ConnectedCount = $Connected.count
    $NeverConnected = ($AllWorkspaceConnStatus | ?{$_.LastConnectionTime -eq "Never"}).count
        
    Write-Verbose "Getting Directory Info..."
    if($UseSessionToken){
        $DirectoryInfo = get-wksworkspaceDirectories -DirectoryID $DirectoryID -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
        
    } else {
        $DirectoryInfo = get-wksworkspaceDirectories -DirectoryID $DirectoryID

        }
    
    
    $Subnets = $DirectoryInfo.SubnetIDs

    $SubnetInfo = foreach($Subnet in $Subnets){
        $CurrSubnet = $null
        if($UseSessionToken){
            $CurrSubnet = get-ec2subnet -subnetid $Subnet -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
            
        } else {
            $CurrSubnet = get-ec2subnet -subnetid $Subnet
    
            }
        
        [pscustomobject]@{"CidrBlock"="$($CurrSubnet.CidrBlock)";"AvailableAddresses"="$($CurrSubnet.AvailableIpAddressCount)"}
    }



    if($Readable){
        
        Write-host "        ~~ Workspaces Status ~~" -ForegroundColor Red
        Write-host ""
        Write-host "    Total Number of Workspaces: " -nonewline
        Write-host "$($Allworkspaces.count)" -ForegroundColor green
        
        Write-host "Workspaces Currently Connected: " -nonewline
        Write-host "$ConnectedCount" -ForegroundColor green
        Write-host "    Workspaces Never Connected: " -nonewline
        Write-host "$NeverConnected" -ForegroundColor Yellow
        Write-host ""
        Write-host "Directory Info:"
        Write-host "  Subnets:"
        Write-host "     CIDR Block`t`tAvailable Addresses"
        Write-host "     ~~~~~~~~~~`t`t~~~~~~~~~~~~~~~~~~~"
        Foreach ($IndSubnet in $SubnetInfo){
            Write-host "     $($IndSubnet.cidrblock)`t`t$($IndSubnet.AvailableAddresses)"
        }
        Write-host ""
    } else {
        [pscustomobject]@{
            "TotalWorkspaces" = "$($Allworkspaces.count)";
            "WorkspacesConnected" = $ConnectedCount;
            "WorkspacesNeverConnected" = $NeverConnected;
            "SubnetInfo" = $SubnetInfo
            }
            
        }
    
    

}

Function Get-LOEWorkspaceInfo {
    Param(
        [string]$Username,
        [string]$DirectoryID = $global:DefaultDir,
        [switch]$UseSessionToken,
        [pscustomobject]$TempSessionArgs = $Global:SessionArgs
    )
    
    if($Username){
        if($UseSessionToken){
            $ConnStatus = Get-LOEWorkspaceConnectionStatus -username $Username -UseSessionToken
            
        } else {
            $ConnStatus = Get-LOEWorkspaceConnectionStatus -username $Username
    
            }
        
        
    } else {
        if($UseSessionToken){
            $ConnStatus = Get-LOEWorkspaceConnectionStatus -UseSessionToken
            
        } else {
            $ConnStatus = Get-LOEWorkspaceConnectionStatus
    
            }
        
    }

    if($ConnStatus){
        foreach ($Instance in $Connstatus) {
            if($UseSessionToken){
                $Tags = get-wkstag -workspaceid $Instance.workspaceid -AccessKey $TempSessionArgs.Credentials.AccessKeyID -SecretAccessKey $TempSessionArgs.Credentials.SecretAccesskey -SessionToken $TempSessionArgs.Credentials.SessionToken
                
            } else {
                $Tags = get-wkstag -workspaceid $Instance.workspaceid
        
                }
            
                $TagsString= $Tags | %{"Key=$($_.Key)`;Value=$($_.Value)"}
            $Instance | Add-Member -MemberType NoteProperty -Name "Tags" -Value $Tags
            $Instance | Add-Member -MemberType NoteProperty -Name "TagsString" -Value $TagsString
            

            $Instance
        }
    } else {
        
            #Not a Valid User
            [pscustomobject]@{
                "Username" = $Username
                "ConnectionStatus" = "User not found"
                "WorkspaceID"  = "User not found"
                "ComputerName" = "User not found"
                "LastConnectionTime"  = "User not found"
                "Bundle" = "User not found"
                "Tags" = "User not found"
                "TagsString" = "User not found"
            }
        
    }

}

