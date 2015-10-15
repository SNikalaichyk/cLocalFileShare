# cLocalFileShare

The **cLocalFileShare** module contains the **cLocalFileShare** DSC resource that provides a mechanism to manage local file shares.

*Supports Windows Server 2008 R2 and later.*

You can also download this module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/cLocalFileShare/).

## Resources

### cLocalFileShare

* **Ensure**: Indicates if the share exists. Set this property to `Absent` to ensure that the share does not exist. Setting it to `Present` (the default value) ensures that the share exists.
* **Name**: Indicates the name of the share.
* **Path**: Indicates the path to the location of the folder to share.
* **ConcurrentUserLimit**: Indicates the number of users allowed to concurrently use the share. To set the limit at the maximum number, set this property to zero.
* **Description**: Indicates an optional description for the share.
* **FullAccess**: Indicates which accounts are granted Full Control permission to access the share.
* **ChangeAccess**: Indicates which accounts are granted Change permission to access the share.
* **ReadAccess**: Indicates which accounts are granted Read permission to access the share.
* **NoAccess**: Indicates which accounts are denied access to the share.

## Versions

### 1.0.1 (October 15, 2015)

* Minor update.

### 1.0.0 (October 5, 2015)

* Initial release with the following resources:
  - **cLocalFileShare**.

## Examples

This configuration will create a directory and two local file shares.

```powershell

configuration Sample_cLocalFileShare
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cLocalFileShare

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type = 'Directory'
    }

    cLocalFileShare Share1
    {
        Ensure = 'Present'
        Name = 'Share-1'
        Path = 'C:\TestDirectory'
        Description = 'Created by the cLocalFileShare DSC resource'
        ConcurrentUserLimit = 10
        FullAccess = 'NT AUTHORITY\SYSTEM'
        ChangeAccess = 'BUILTIN\Administrators'
        ReadAccess = 'NT AUTHORITY\Authenticated Users'
        NoAccess = 'BUILTIN\Guests'
        DependsOn = '[File]TestDirectory'
    }

    cLocalFileShare Share2
    {
        Ensure = 'Present'
        Name = 'Share-2'
        Path = 'C:\TestDirectory'
        ConcurrentUserLimit = 0
        Description = 'Created by the cLocalFileShare DSC resource'
        ReadAccess = 'Everyone'
        DependsOn = '[File]TestDirectory'
    }
}

Sample_cLocalFileShare -OutputPath "$Env:SystemDrive\Sample_cLocalFileShare"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cLocalFileShare" -Force -Verbose -Wait

Get-DscConfiguration


```

