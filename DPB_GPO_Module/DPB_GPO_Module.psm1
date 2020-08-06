function Get-UsersGPO {
    <#
		.SYNOPSIS
		    Grabs the Group Policy information from target usernames from target computers.
		.DESCRIPTION
		    Grabs the group policy information from target usernames fomr target computers and presents useful information. 
        .PARAMETER Usernames
            [string[]] The usernames that you will be targeting.
        .PARAMETER ComputerNames
		    [string[]] The Computer Names of each target computer. 
		.PARAMETER Credentials
		    if you choose to use a credential, this is where you would add this information.
            if you choose not to use credential, then the script will use the currently running credentials. 
		.EXAMPLE
            Get-UsersGPO -computernames <server1>,<server2> -usernames bob,jim,frank

            The command will search each server for bob's group policy information, then jim, then franks.

            ComputerName      : <server1>
            Username          : bob
            Name              : Local Group Policy
            Enabled           : True
            AccessDenied      : False
            TotalMilliseconds : 0
            Errors            : 0
            SomOrder          : 1
            AppliedOrder      : 1
            LinkOrder         : 1
            NoOverride        : False
		.EXAMPLE
            Get-UsersGPO -computernames <server1>,<server2> -usernames bob,jim,frank -Credientials (get-credential)

            The command will search each server for bob's group policy information, then jim, then franks using the credentials of the supplied credentials. 
            
            ComputerName      : <server1>
            Username          : bob
            Name              : Local Group Policy
            Enabled           : True
            AccessDenied      : False
            TotalMilliseconds : 0
            Errors            : 0
            SomOrder          : 1
            AppliedOrder      : 1
            LinkOrder         : 1
            NoOverride        : False
		.LINK
		    https://bolding.us
		.NOTES
            Author: David Bolding
            Site: https://www.bolding.us
	#>   
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')]
        [String[]]$Computernames,
        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the username you wish to target.",
            Mandatory = $true)]
        [Alias('Samaccountname')][string[]]$usernames,
        [Parameter(HelpMessage = "Allows for custom credentials.")][System.Management.Automation.PSCredential]$Credentials
    )
    foreach ($username in $usernames) {
        $SID = $Null 
        try {
            if ($PSBoundParameters.ContainsKey('Credentials')) {
                $SID = (Get-ADUser -Identity $username -Credential $Credentials).sid.value -replace "-", "_"
            }
            else {
                $SID = (Get-ADUser -Identity $username).sid.value -replace "-", "_"
            }
            
        }
        Catch {
            Write-Warning "$username does not exist in active directory."
            break
        }
        if ($null -ne $SID) {
            foreach ($computername in $Computernames) {
                try {
                    if ($PSBoundParameters.ContainsKey('Credentials')) {
                        $CIMSession = New-CimSession -ComputerName $computername -Credential $Credentials 
                        $Policies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -CimSession $CimSession 2>$Null
                        $Times = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -CimSession $CIMSession 2>$Null
                        $GPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -CimSession $CimSession 2>$Null
                        Remove-CimSession $CIMSession
                    }
                    else {
                        $Policies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computername 2>$Null
                        $Times = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computername 2>$Null
                        $GPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computername 2>$Null
                    }
                }
                catch {
                    Write-Warning "Unable to Capture Data from $Computername with $Username - $SID"
                    break
                }
                foreach ($Policy in $Policies) {
                    $Link = $GPLink | Where-Object { $_.gpo.id -like $Policy.id }
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
                    $Temp = $Times | Where-Object { $_.extensionGuid -like "*$($Policy.extensionIds[0])*" }
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
                        ComputerName      = $Policy.PSComputerName
                        Username          = $username
                        Name              = $Policy.name
                        Enabled           = $Policy.enabled
                        AccessDenied      = $Policy.accessDenied
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
    }
}
function Get-PCGPO {
    <#
		.SYNOPSIS
		    Grabs the applied group policy information applied to target computer.
		.DESCRIPTION
		    Grabs the applied group policy information applied to target computer.
		.PARAMETER ComputerNames
		    [string[]] The Computer Names of each target computer. 
		.PARAMETER Credentials
		    if you choose to use a credential, this is where you would add this information.
            if you choose not to use credential, then the script will use the currently running credentials. 
		.EXAMPLE
		    Get-PCGPO -ComputerNames <Server1>,<Server2>

            This will use the currently running login to access server 1 and server 2. Then it 
            will produce the GPO information.
		.EXAMPLE
            Get-PCGPO -ComputerNames <OffDomainComputer> -Credentials (get-credential)		    

            This will prompt you to put in the credential information needed to access the off domain
            computer and apply the gpo settings to it. 
		.LINK
		    https://bolding.us
		.NOTES
            Author: David Bolding
            Site: https://www.bolding.us
	#>    
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')]
        [String[]]$Computernames,
        [Parameter(HelpMessage = "Allows for custom credentials.")][System.Management.Automation.PSCredential]$Credentials
    )

    #we start the loop of computers
    foreach ($ComputerName in $Computernames) {
        
        #We test if the computer is on.
        if (Test-Connection -ComputerName $ComputerName -Quiet -Count 1) {
            Try {

                #We check if we want to use alternate credentials
                if ($PSBoundParameters.ContainsKey('Credentials')) {

                    #We try older wmiobjects as many of our system still understands wmiobjects with the credentials. We are grabbing the GPO information
                    $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computername -Credential $Credentials

                    #Next we grab the GPLink information to be used to show the link levels. We do this with credentials
                    $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computername -Credential $Credentials
                }
                else {

                    #We try to capture computer's gpo with the shells current credentials.
                    $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computername

                    #We try to capture the computer's gp linking with the shell's current credentials.
                    $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computername
                }
            }
            Catch {
                Try {

                    #Powershell 7 and above does not understand get-wmiobject anymore. Thus we need to use Cim objects. 
                    if ($PSBoundParameters.ContainsKey('Credentials')) {

                        #We create a CIMSession for the target computer with our custom credentials.
                        $CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credentials

                        #We try to pull the RSOP_GPO information using the CIM session created above
                        $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -CimSession $CimSession

                        #We try to pull the RSOP_GPlink information using the CMI Session created above
                        $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -CimSession $CimSession

                        #Now we cleanup the cim session
                        Remove-CimSession -CimSession $CimSession 
                    }
                    else {
                        #We try to grab the rsop_GPO information using the shell's credentials.
                        $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computername

                        #We try to grab the rsop_gplink informatin with the shell's credentials
                        $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computername
                    }
                }
                Catch {
                    Write-Warning "Failed to capture group policy information."
                    break
                }  
            }  
            #We test our return information
            if (($null -ne $returns) -or ($null -ne $returnLinks)) {

                #we start looping the returns
                foreach ($Return in $returns) {

                    #we search the returnlinks for the gpo id information to match them up.
                    $TempLink = $returnLinks | Where-Object { $_.gpo.id -like $return.id }

                    #Then we create the psobject and display the information.
                    [PSCustomObject]@{
                        ComputerName = $Computername
                        GPOName      = $Return.name 
                        Enabled      = $TempLink.enabled
                        LinkOrder    = $TempLink.linkOrder
                        SomOrder     = $templink.somOrder
                    }
                }
            }
            else {
                Write-Warning "No Information was gathered for $Computername"
            }
        }
        else {
            Write-Warning "$Computername Offline"
        }
    }   
}
function Get-GroupPolicyName {
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
		    https://bolding.us
		.NOTES
            Author: David Bolding
            Site: https://www.bolding.us
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
		    https://bolding.us
		.NOTES
            Author: David Bolding
            Site: https://www.bolding.us
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
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName,
        [Parameter(HelpMessage = "Allows for custom credentials.")][System.Management.Automation.PSCredential]$Credentials
    )
    if (Test-Connection -ComputerName $Computername -Quiet -Count 1) {
        $GPO = Get-GroupPolicyName -GroupPolicyName $GroupPolicyName
        If ($null -ne $GPO) {
            $Domain = (Get-ADDomain).netbiosname
            if ($PSBoundParameters.ContainsKey('Credentials')) {
                $CIMSession = New-CimSession -ComputerName $computername -Credential $Credentials
                $Users = (Get-CimInstance -ClassName win32_account -CimSession $CIMSession | Where-Object { $_.domain -like "*$Domain*" }).name 
                Remove-CimSession -CimSession $CIMSession
            }
            else {
                $Users = (Get-CimInstance -ClassName win32_account -ComputerName $Computername | Where-Object { $_.domain -like "*$Domain*" }).name
            }
            if ($PSBoundParameters.ContainsKey('Credentials')) {
                $UsersGPOs = Get-UsersGPO -Computernames $Computername -usernames $Users -Credentials $Credentials
            }
            else {
                $UsersGPOs = Get-UsersGPO -Computernames $Computername -usernames $Users 
            }
            $UsersGPOs | Where-Object { $_.name -like "$($GPO.displayname)" }
        }
        else {
            Write-Warning "$GroupPolicyName does not exist."
        }
    }
    else {
        Write-Warning "$Computername offline."
    }
    
}
