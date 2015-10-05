
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

