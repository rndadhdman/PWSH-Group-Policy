function Get-ComputerPCGPO {
    <#
		.SYNOPSIS
		    Grabs the Group Policy Information from a collection of computers or a single user from a collection of computers.
		.DESCRIPTION
            Get-ComputerPCGPO grabs group policy informatin from a collection of computers. Or you can target a single user on those collection of computers and grab it's group policy information.    
        .PARAMETER ComputerName
            [string[]] The Computer Names of each target computer. 
        .PARAMETER Username
            [string] The username of a target user on this computer. 
		.PARAMETER Credential
		    if you choose to use a credential, this is where you would add this information.
            if you choose not to use credential, then the script will use the currently running Credential. 
		.EXAMPLE
		    Get-ComputerPCGPO -ComputerName [string[]]

            This will use the currently running login to access server 1 and server 2. Then it 
            will produce the GPO information.
		.EXAMPLE
            Get-PCGComputerPCGPOPO -ComputerName [string[]] -Credential (get-credential)		    

            This will prompt you to put in the credential information needed to access the off domain
            computer and apply the gpo settings to it. 
        .EXAMPLE
		    Get-ComputerPCGPO -ComputerName [string[]] -username [string]

            This will use the currently running login to access each computer in the collection and grab a single username group policy information.
		.EXAMPLE
            Get-ComputerPCGPO -ComputerName [string[]] -Credential (get-credential) -username [string]

            This will use the supplied credentials to access each computer in the collection and grab a single username group policy information.
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#>    
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')]
        [String[]]$Computername,
        [Parameter(HelpMessage = "Target a single user in the list of users")]
        [Alias('Samaccountname')]
        [string]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )

    #we start the loop of computers
    foreach ($Computer in $Computername) {

        #Check for the username flag. If it's present, then we start the username process. 
        if ($PSBoundParameters.ContainsKey('Username')) {
            $SID = $Null 
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $SID = (Get-ADUser -Identity $username -Credential $Credential).sid.value -replace "-", "_"
                }
                else {
                    $SID = (Get-ADUser -Identity $username).sid.value -replace "-", "_"
                }
            }
            Catch {
                Write-Warning "$username does not exist in active directory."
                break
            }
        }
        #We test if the computer is on.
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Username')) {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        #We try older wmiobjects as many of our system still understands wmiobjects with the Credential. We are grabbing the GPO information
                        $UserPolicies = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer -Credential $Credential 2>$Null
                        $UserTimes = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer -Credential $Credential 2>$Null
                        $UserGPLink = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer -Credential $Credential 2>$Null
                    }
                    else {
                        $UserPolicies = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer 2>$Null
                        $UserTimes = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer 2>$Null
                        $UserGPLink = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer 2>$Null
                    }
                }
                else {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer -Credential $Credential
                        $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer -Credential $Credential
                    }
                    else {
                        $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer
                        $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer
                    }
                }                
            }
            Catch {
                Try {

                    #Powershell 7 and above does not understand get-wmiobject anymore. Thus we need to use Cim objects. 
                    if ($PSBoundParameters.ContainsKey('Username')) {
                        if ($null -ne $SID) {
                            if ($PSBoundParameters.ContainsKey('Credential')) {
                                $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                                $UserPolicies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -CimSession $CimSession 2>$Null
                                $UserTimes = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -CimSession $CIMSession 2>$Null
                                $UserGPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -CimSession $CimSession 2>$Null
                                Remove-CimSession $CIMSession
                            }
                            else {
                                $UserPolicies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer 2>$Null
                                $UserTimes = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer 2>$Null
                                $UserGPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer 2>$Null
                            }
                        }    
                    }
                    else {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            $CimSession = New-CimSession -ComputerName $Computer -Credential $Credential
                            $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -CimSession $CimSession
                            $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -CimSession $CimSession
                            Remove-CimSession -CimSession $CimSession 
                        }
                        else {
                            $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer
                            $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer
                        }
                    }                    
                }
                Catch {
                    Write-Warning "Failed to capture group policy information."
                    break
                }  
            }  
            #We test our return information
            if ($PSBoundParameters.ContainsKey('Username')) {
                if ($null -ne $SID) {
                    foreach ($UserPolicy in $UserPolicies) {
                        $Link = $UserGPLink | Where-Object { $_.gpo.id -like $UserPolicy.id }
                        if ($null -ne $link) {
                            $SomOrder = $link.somOrder
                            $AppliedOrdered = $link.appliedOrder
                            $LinkedOrder = $link.linkorder
                            $NoOverride = $link.noOverride
                        }
                        else {
                            $SomOrder = $null
                            $AppliedOrdered = $null
                            $LinkedOrder = $null
                            $NoOverride = $null
                        }
                        $Temp = $UserTimes | Where-Object { $_.extensionGuid -like "*$($UserPolicy.extensionIds[0])*" }
                        try {
                            $TotalTime = ($temp.endtime - $temp.begintime).totalmilliseconds
                        }
                        catch {
                            $TotalTime = '0'
                        }
                        if ($null -ne $Temp) {
                            $Errors = $Temp.error
                            $TotalTime = $TotalTime
                        }
                        else {
                            $Errors = ""
                            $TotalTime = $TotalTime
                        }                  
                        [pscustomobject]@{
                            ComputerName      = $UserPolicy.PSComputerName
                            Username          = $username
                            Name              = $UserPolicy.name
                            Enabled           = $UserPolicy.enabled
                            AccessDenied      = $UserPolicy.accessDenied
                            TotalMilliseconds = $TotalTime
                            Errors            = $Errors
                            SomOrder          = $SomOrder
                            AppliedOrder      = $AppliedOrdered
                            LinkOrder         = $LinkedOrder
                            NoOverride        = $NoOverride
                        }
                    }
                }
            }
            else {
                if (($null -ne $returns) -or ($null -ne $returnLinks)) {
                    foreach ($Return in $returns) {
                        $TempLink = $returnLinks | Where-Object { $_.gpo.id -like $return.id }
                        [PSCustomObject]@{
                            ComputerName = $Computer
                            GPOName      = $Return.name 
                            Enabled      = $TempLink.enabled
                            LinkOrder    = $TempLink.linkOrder
                            SomOrder     = $templink.somOrder
                        }
                    }
                }
                else {
                    Write-Warning "No Information was gathered for $Computer"
                }
            }
            
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }   
}

function Get-GPOName {
    <#
		.SYNOPSIS
		    Finds a group policy by a name given.
		.DESCRIPTION
		    If you can't remember a group policy's full name, yo ucan find it with this script. 
        .PARAMETER GroupPolicyName
            The name you are searching for. 
		.EXAMPLE
            Get-GroupPolicyName -GroupPolicyName "Firewall"

            Finds the group policy with the matching name. 
            
            DisplayName      : Domain Firewall
            DomainName       : Domain
            Owner            : User
            Id               : 00000000-0000-0000-0000-000000000000
            GpoStatus        : AllSettingsEnabled
            Description      :
            CreationTime     : 7/9/2003 11:03:33 AM
            ModificationTime : 7/9/2003 12:55:20 PM
            UserVersion      :
            ComputerVersion  :
            WmiFilter        :
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#> 
    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName
    )
    $AllGPOs = Get-GPO -All    
    $AllGPOs | Where-Object { $_.DisplayName -like "*$GroupPolicyName*" }
}
function Search-UsersOnComputerForGPO {
    <#
		.SYNOPSIS
		    Finds all users with a given gpo name on target server.
		.DESCRIPTION
		    Finds all users with a given gpo name on target server.
        .PARAMETER Computername
            Target computer to search the gpo of. 
        .PARAMETER GroupPolicyName
            The name you are searching for. 
        .PARAMETER Credientals
            Credientals to use on target computer
		.EXAMPLE
            
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#> 
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')][String]$Computername,
        [Parameter(
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName,
        [Parameter(HelpMessage = "Allows for custom credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if (Test-Connection -ComputerName $Computername -Quiet -Count 1) {
        $GPO = Get-GPOName -GroupPolicyName $GroupPolicyName
        If ($null -ne $GPO) {
            $Domain = (Get-ADDomain).netbiosname
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $CIMSession = New-CimSession -ComputerName $computername -Credential $Credential
                $Users = (Get-CimInstance -ClassName win32_account -CimSession $CIMSession | Where-Object { $_.domain -like "*$Domain*" }).name 
                Remove-CimSession -CimSession $CIMSession
            }
            else {
                $Users = (Get-CimInstance -ClassName win32_account -ComputerName $Computername | Where-Object { $_.domain -like "*$Domain*" }).name
            }
            foreach ($user in $Users) { }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $UsersGPOs = Get-ComputerPCGPO -Computernames $Computername -usernames $User -Credentials $Credential
            }
            else {
                $UsersGPOs = Get-ComputerPCGPO -Computernames $Computername -usernames $User 
            }
            $UsersGPOs | Where-Object { $_.name -like "$($GPO.displayname)" }
        }
    }
    else {
        Write-Warning "$GroupPolicyName does not exist."
    }
}

