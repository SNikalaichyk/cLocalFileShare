<#
Author  : Serge Nikalaichyk (https://www.linkedin.com/in/nikalaichyk)
Version : 1.0.1
Date    : 2015-10-15
#>


function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        $Path
    )

    if ($Path.EndsWith('\'))
    {
        $Path = $Path.TrimEnd('\')
    }

    $Share = Get-WmiObject -Class Win32_Share -Filter "Name = '$Name' AND Type = 0"

    if ($Share)
    {
        if ($Share.Path -eq $Path)
        {
            Write-Verbose -Message  "File share '$Name' with path '$Path' was found."

            $EnsureResult = 'Present'

            $ShareAccessSplit = Get-cLocalFileShareAccess -Name $Name | ConvertFrom-cLocalFileShareAccess
        }
        else
        {
            throw "File share '$Name' already exists and is targeting to path '$($Share.Path)'."
        }
    }
    else
    {
        Write-Verbose -Message  "File share '$Name' with path '$Path' could not be found."

        $EnsureResult = 'Absent'
    }

    $ReturnValue = @{
            Ensure = $EnsureResult
            Name = $Name
            Path = $Path
            ConcurrentUserLimit = [UInt32]$Share.MaximumAllowed
            Description = $Share.Description
            FullAccess = [String[]]@($ShareAccessSplit.FullAccess)
            ChangeAccess = [String[]]@($ShareAccessSplit.ChangeAccess)
            ReadAccess = [String[]]@($ShareAccessSplit.ReadAccess)
            NoAccess = [String[]]@($ShareAccessSplit.NoAccess)
        }

    return $ReturnValue

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $ConcurrentUserLimit,

        [Parameter(Mandatory = $false)]
        [String]
        $Description,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $FullAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ChangeAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReadAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $NoAccess
    )

    if ($Path.EndsWith('\'))
    {
        $Path = $Path.TrimEnd('\')
    }

    $TargetResource = Get-TargetResource -Name $Name -Path $Path

    if ($Ensure -eq 'Absent')
    {
        if ($TargetResource.Ensure -eq 'Absent')
        {
            $InDesiredState = $true
        }
        else
        {
            $InDesiredState = $false
        }
    }
    elseif ($Ensure -eq 'Present')
    {
        if ($TargetResource.Ensure -eq 'Absent')
        {
            $InDesiredState = $false
        }
        else
        {
            $InDesiredState = $true

            $PSBoundParameters.Keys.Where({$_ -in @('Name', 'Path', 'ConcurrentUserLimit', 'Description', 'Ensure')}).ForEach(
                {
                    if (Compare-Object -ReferenceObject $PSBoundParameters.Item($_) -DifferenceObject $TargetResource.Item($_))
                    {
                        "Property '{0}': Current value: '{1}'; Desired value: '{2}'." -f
                            $_, ($TargetResource.Item($_) -join ', '), ($PSBoundParameters.Item($_) -join ', ') |
                        Write-Verbose

                        $InDesiredState = $false
                    }
                }
            )

            # Normalize and test access-related property values
            if ($PSBoundParameters.Keys.Where({$_ -in @('FullAccess', 'ChangeAccess', 'ReadAccess', 'NoAccess')}))
            {
                Write-Verbose -Message "Testing access-related property values."

                $ReferenceAccessSplit = ConvertTo-cLocalFileShareAccess -FullAccess $FullAccess -ChangeAccess $ChangeAccess -ReadAccess $ReadAccess -NoAccess $NoAccess |
                    ConvertFrom-cLocalFileShareAccess

                if (Compare-Object -ReferenceObject $ReferenceAccessSplit.FullAccess -DifferenceObject $TargetResource.FullAccess)
                {
                    "Property '{0}': Current value: '{1}'; Desired value: '{2}'." -f
                        'FullAccess', ($TargetResource.FullAccess -join ', '), ($ReferenceAccessSplit.FullAccess -join ', ') |
                    Write-Verbose

                    $InDesiredState = $false
                }

                if (Compare-Object -ReferenceObject $ReferenceAccessSplit.ChangeAccess -DifferenceObject $TargetResource.ChangeAccess)
                {
                    "Property '{0}': Current value: '{1}'; Desired value: '{2}'." -f
                        'ChangeAccess', ($TargetResource.ChangeAccess -join ', '), ($ReferenceAccessSplit.ChangeAccess -join ', ') |
                    Write-Verbose

                    $InDesiredState = $false
                }

                if (Compare-Object -ReferenceObject $ReferenceAccessSplit.ReadAccess -DifferenceObject $TargetResource.ReadAccess)
                {
                    "Property '{0}': Current value: '{1}'; Desired value: '{2}'." -f
                        'ReadAccess', ($TargetResource.ReadAccess -join ', '), ($ReferenceAccessSplit.ReadAccess -join ', ') |
                    Write-Verbose

                    $InDesiredState = $false
                }

                if (Compare-Object -ReferenceObject $ReferenceAccessSplit.NoAccess -DifferenceObject $TargetResource.NoAccess)
                {
                    "Property '{0}': Current value: '{1}'; Desired value: '{2}'." -f
                        'NoAccess', ($TargetResource.NoAccess -join ', ') , ($ReferenceAccessSplit.NoAccess -join ', ') |
                    Write-Verbose

                    $InDesiredState = $false
                }
            }
        }
    }

    if ($InDesiredState -eq $true)
    {
        Write-Verbose -Message "The target resource is already in the desired state. No action is required."
    }
    else
    {
        Write-Verbose -Message "The target resource is not in the desired state."
    }

    return $InDesiredState

}


function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $ConcurrentUserLimit,

        [Parameter(Mandatory = $false)]
        [String]
        $Description,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $FullAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ChangeAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReadAccess,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $NoAccess
    )

    if (-not $PSCmdlet.ShouldProcess($Name))
    {
        return
    }

    if ($Path.EndsWith('\'))
    {
        $Path = $Path.TrimEnd('\')
    }

    $TargetResource = Get-TargetResource -Name $Name -Path $Path

    if ($Ensure -eq 'Absent')
    {
        if ($TargetResource.Ensure -eq 'Present')
        {
            Write-Verbose -Message  "Removing file share '$Name'."

            Remove-cLocalFileShare -Name $Name -Confirm:$false
        }
    }
    elseif ($Ensure -eq 'Present')
    {
        if ($TargetResource.Ensure -eq 'Absent')
        {
            Write-Verbose -Message  "Creating file share '$Name' with path '$Path'."

            New-cLocalFileShare -Name $Name -Path $Path -ErrorAction Stop

            $TargetResource = Get-TargetResource -Name $Name -Path $Path
        }

        # Compare permissions
        $ReferenceAccess = ConvertTo-cLocalFileShareAccess -FullAccess $FullAccess -ChangeAccess $ChangeAccess -ReadAccess $ReadAccess -NoAccess $NoAccess

        if ($ReferenceAccess)
        {
            $ReferenceAccessSplit = $ReferenceAccess | ConvertFrom-cLocalFileShareAccess

            if (
                (Compare-Object -ReferenceObject $ReferenceAccessSplit.FullAccess -DifferenceObject $TargetResource.FullAccess) -or
                (Compare-Object -ReferenceObject $ReferenceAccessSplit.ChangeAccess -DifferenceObject $TargetResource.ChangeAccess) -or 
                (Compare-Object -ReferenceObject $ReferenceAccessSplit.ReadAccess -DifferenceObject $TargetResource.ReadAccess) -or
                (Compare-Object -ReferenceObject $ReferenceAccessSplit.NoAccess -DifferenceObject $TargetResource.NoAccess)
            )
            {
                Write-Verbose -Message "Setting file share permissions."

                Set-cLocalFileShareAccess -Name $Name -AccessRuleCollection $ReferenceAccess
            }
        }
        else
        {
            Write-Verbose -Message "File share permissions will not be modified."
        }

        $PSBoundParameters.GetEnumerator() |
        Where-Object {$_.Key -in (Get-Command -Name Set-cLocalFileShare).Parameters.Keys} |
        ForEach-Object -Begin {$SetParameters = @{}} -Process {$SetParameters.Add($_.Key, $_.Value)}

        if ($SetParameters.Count -ne 0)
        {
            Set-cLocalFileShare @SetParameters
        }
    }

}


Export-ModuleMember -Function Get-TargetResource, Set-TargetResource, Test-TargetResource


#region Helper Functions

function Initialize-cLocalFileShareType
{

    $TypeDefinition = @'
namespace cLocalFileShare
{
    public enum AccessMask
    {
        Read = 1179817,
        Change = 1245631,
        Full = 2032127
    }

    public enum AceType
    {
        Allow = 0,
        Deny = 1
    }

    public class AccessRule
    {
        public string AccountName {get; set;}
        public AceType AccessControlType {get; set;}
        public AccessMask AccessRight {get; set;}

        public AccessRule(string Principal, AceType Type, AccessMask Access)
        {
            AccountName = Principal;
            AccessControlType = Type;
            AccessRight = Access;
        }
    }
}
'@

    if (-not ('cLocalFileShare.AccessRule' -as [Type]))
    {
        Add-Type -TypeDefinition $TypeDefinition
    }

}

Initialize-cLocalFileShareType


function New-cLocalFileShare
{
    [CmdletBinding(ConfirmImpact = 'Medium', SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        $Path
    )
    process
    {
        if ($Path.EndsWith('\'))
        {
            $Path = $Path.TrimEnd('\')
        }

        if ($PSCmdlet.ShouldProcess($Name, 'Create File Share'))
        {
            $Result = ([WmiClass]'Win32_Share').Create($Path, $Name, 0)

            if ($Result)
            {
                if ($Result.ReturnValue -eq 0)
                {
                    Write-Verbose -Message  "File share '$Name' was created."
                }
                else
                {
                    Write-Error -Message "Unable to create file share '$Name'. Return code: '$($Result.ReturnValue)'."

                    return
                }
            }
        }
    }
}


function Remove-cLocalFileShare
{
    [CmdletBinding(ConfirmImpact = 'High', SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    process
    {
        $Share = Get-WmiObject -Class Win32_Share -Filter "Name = '$Name' AND Type = 0"

        if (-not $Share)
        {
            Write-Error -Message "File share '$Name' could not be found."

            return
        }

        if ($PSCmdlet.ShouldProcess($Name, 'Remove File Share'))
        {
            $Result = $Share.Delete()

            if ($Result)
            {
                if ($Result.ReturnValue -eq 0)
                {
                    Write-Verbose -Message  "File share '$Name' was removed."
                }
                else
                {
                    Write-Error -Message "Unable to remove file share '$Name'. Return code: '$($Result.ReturnValue)'."

                    return
                }
            }
            else
            {
                Write-Verbose -Message  "File share '$Name' was not removed."
            }
        }
    }
}


function Set-cLocalFileShare
{
    [CmdletBinding(ConfirmImpact = 'Medium', SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $ConcurrentUserLimit = 0,

        [Parameter(Mandatory = $false)]
        [String]
        $Description = $null
    )
    process
    {
        $Share = Get-WmiObject -Class Win32_Share -Filter "Name = '$Name' AND Type = 0"

        if (-not $Share)
        {
            Write-Error -Message "File share '$Name' could not be found."

            return
        }

        if (-not $PSCmdlet.ShouldProcess($Name, 'Set File Share'))
        {
            return
        }

        if ($PSBoundParameters.Keys.Where({$_ -in 'ConcurrentUserLimit', 'Description'}))
        {
            if ($PSBoundParameters.ContainsKey('ConcurrentUserLimit'))
            {
                if ($ConcurrentUserLimit -eq 0)
                {
                    # The SetShareInfo method of the Win32_Share class cannot set the AllowMaximum property to True
                    Invoke-Expression -Command "$Env:SystemRoot\System32\net.exe Share '$Name' /Unlimited" | Out-Null
                }
            }
            else
            {
                $ConcurrentUserLimit = $Share.MaximumAllowed
            }

            if (-not $PSBoundParameters.ContainsKey('Description'))
            {
                $Description = $Share.Description
            }

            $Result = $Share.SetShareInfo($ConcurrentUserLimit, $Description, $null)

            if ($Result)
            {
                if ($Result.ReturnValue -eq 0)
                {
                    Write-Verbose -Message  "File share '$Name' was set."
                }
                else
                {
                    Write-Error -Message "Unable to set file share '$Name'. Return code: '$($Result.ReturnValue)'."

                    return
                }
            }
            else
            {
                Write-Verbose -Message  "File share '$Name' was not set."
            }
        }
    }
}


function Get-cLocalFileShareAccess
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    begin
    {
        Initialize-cLocalFileShareType

        $OutputEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[cLocalFileShare.AccessRule]'
    }
    process
    {
        $ShareSecurity = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name = '$Name'"

        if (-not $ShareSecurity)
        {
            Write-Error -Message "The Win32_LogicalShareSecuritySetting object could not be found. Please ensure file share '$Name' exists."

            return
        }

        $SecurityDescriptor = $ShareSecurity.GetSecurityDescriptor().Descriptor
        $SecurityDescriptor.DACL |
        ForEach-Object {
            $Identity = Resolve-IdentityReference -Identity $_.Trustee.SIDString -Verbose:$false
            $OutputEntries.Add((New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $Identity.Name, $_.AceType, $_.AccessMask))
        }
    }
    end
    {
        return $OutputEntries
    }
}


function Set-cLocalFileShareAccess
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $AccessRuleCollection
    )
    begin
    {
        Initialize-cLocalFileShareType

        [cLocalFileShare.AccessRule[]]$AccessRuleCollection = $AccessRuleCollection
    }
    process
    {
        $ShareSecurity = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name = '$Name'"

        if (-not $ShareSecurity)
        {
            Write-Error -Message "The Win32_LogicalShareSecuritySetting object could not be found. Please ensure file share '$Name' exists."

            return
        }

        if ($PSCmdlet.ShouldProcess($Name, 'Set Share Permissions'))
        {
            $AccessRuleCollection |
            Select-Object -PipelineVariable AccessRule |
            ForEach-Object -Begin {

                $SecurityDescriptor = ([WmiClass]'Win32_SecurityDescriptor').CreateInstance()
                $SecurityDescriptor.ControlFlags = 32772

            } -Process {

                "Adding '{0}' '{1}' access permission for '{2}'." -f $AccessRule.AccessControlType, $AccessRule.AccessRight, $AccessRule.AccountName |
                Write-Verbose 

                $Trustee = ([WmiClass]'Win32_Trustee').CreateInstance()
                $Trustee.SIDString = (Resolve-IdentityReference -Identity $AccessRule.AccountName -Verbose:$false).SID
                $Ace = ([WmiClass]'Win32_ACE').CreateInstance()
                $Ace.AccessMask = $AccessRule.AccessRight
                $Ace.AceFlags = 0
                $Ace.AceType = $AccessRule.AccessControlType
                $Ace.Trustee = $Trustee
                $SecurityDescriptor.DACL += $Ace

            } -End {

                if ($SecurityDescriptor.DACL.Count -ne 0)
                {
                    $Result = $ShareSecurity.SetSecurityDescriptor($SecurityDescriptor)

                    if ($Result.ReturnValue -eq 0)
                    {
                        "Permissions were set on file share '{0}'." -f $ShareSecurity.Name |
                        Write-Verbose
                    }
                    else
                    {
                        "Failed to set permissions on file share '{0}'. Return code: '{1}'." -f $ShareSecurity.Name, $Result.ReturnValue |
                        Write-Error

                        return
                    }
                }
                else
                {
                    "Permissions were not set on file share '{0}'." -f $ShareSecurity.Name |
                    Write-Verbose
                }

            }
        }
    }
}


function ConvertFrom-cLocalFileShareAccess
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]
        $InputObject
    )
    begin
    {
        $ReturnValue = [PSCustomObject]@{
                FullAccess = @()
                ChangeAccess = @()
                ReadAccess = @()
                NoAccess = @()
            }
    }
    process
    {
        foreach ($Item in $InputObject)
        {
            if ($Item.AccessRight -eq 'Full' -and $Item.AccessControlType -eq 'Allow')
            {
                $ReturnValue.FullAccess += $Item.AccountName
            }
            elseif ($Item.AccessRight -eq 'Change' -and $Item.AccessControlType -eq 'Allow')
            {
                $ReturnValue.ChangeAccess += $Item.AccountName
            }
            elseif ($Item.AccessRight -eq 'Read' -and $Item.AccessControlType -eq 'Allow')
            {
                $ReturnValue.ReadAccess += $Item.AccountName
            }            
            elseif ($Item.AccessControlType -eq 'Deny')
            {
                $ReturnValue.NoAccess += $Item.AccountName
            }
        }
    }
    end
    {
        return $ReturnValue
    }
}


function ConvertTo-cLocalFileShareAccess
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $FullAccess = $null,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $ChangeAccess = $null,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $ReadAccess = $null,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $NoAccess = $null
    )
    begin
    {
        Initialize-cLocalFileShareType

        $InputEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[cLocalFileShare.AccessRule]'
        $OutputEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[cLocalFileShare.AccessRule]'
    }
    process
    {
        if ($PSBoundParameters.ContainsKey('FullAccess') -and $FullAccess.Count -ne 0)
        {
            $FullAccess |
            Resolve-IdentityReference |
            ForEach-Object {$InputEntries.Add((New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $_.Name, 'Allow', 'Full'))}
        }

        if ($PSBoundParameters.ContainsKey('ChangeAccess') -and $ChangeAccess.Count -ne 0)
        {
            $ChangeAccess |
            Resolve-IdentityReference |
            ForEach-Object {$InputEntries.Add((New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $_.Name, 'Allow', 'Change'))}
        }

        if ($PSBoundParameters.ContainsKey('ReadAccess') -and $ReadAccess.Count -ne 0)
        {
            $ReadAccess |
            Resolve-IdentityReference |
            ForEach-Object {$InputEntries.Add((New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $_.Name, 'Allow', 'Read'))}
        }

        if ($PSBoundParameters.ContainsKey('NoAccess') -and $NoAccess.Count -ne 0)
        {
            $NoAccess |
            Resolve-IdentityReference |
            ForEach-Object {$InputEntries.Add((New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $_.Name, 'Deny', 'Full'))}
        }
    }
    end
    {
        $InputEntries |
        Group-Object -Property AccountName -PipelineVariable EntryGroup |
        ForEach-Object {
            $EntryGroup.Group |
            ForEach-Object -Begin {
                $OutputEntry = New-Object -TypeName cLocalFileShare.AccessRule -ArgumentList $EntryGroup.Name, 'Allow', 'Read'
            } -Process {
                $OutputEntry.AccessControlType = $OutputEntry.AccessControlType -bor $_.AccessControlType
                $OutputEntry.AccessRight = $OutputEntry.AccessRight -bor $_.AccessRight
            } -End {
                $OutputEntries += $OutputEntry
            }
        }

        return $OutputEntries
    }
}


function Resolve-IdentityReference
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $Identity
    )
    process
    {
        try
        {
            Write-Verbose -Message "Resolving identity reference '$Identity'."

            if ($Identity -match '^S-\d-(\d+-){1,14}\d+$')
            {
                [System.Security.Principal.SecurityIdentifier]$Identity = $Identity
            }
            else
            {
                [System.Security.Principal.NTAccount]$Identity = $Identity
            }

            $SID = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
            $NTAccount = $SID.Translate([System.Security.Principal.NTAccount])

            $OutputObject = [PSCustomObject]@{Name = $NTAccount.Value; SID = $SID.Value}

            return $OutputObject
        }
        catch
        {
            "Unable to resolve identity reference '{0}'. Error: '{1}'" -f $Identity, $_.Exception.Message |
            Write-Error

            return
        }
    }
}


#endregion

