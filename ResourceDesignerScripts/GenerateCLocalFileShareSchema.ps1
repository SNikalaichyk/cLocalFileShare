
#requires -Version 4.0 -Modules xDSCResourceDesigner

$ModuleName = 'cLocalFileShare'
$ResourceName = 'cLocalFileShare'

$DscResourceProperties =  @(
    (New-xDscResourceProperty -Type String -Attribute Write -Name Ensure -ValidateSet 'Absent', 'Present' -Description 'Indicates if the share exists. Set this property to Absent to ensure that the share does not exist. Setting it to Present (the default value) ensures that the share exists.')
    (New-xDscResourceProperty -Type String -Attribute Key -Name Name -Description 'Indicates the name of the share.'),
    (New-xDscResourceProperty -Type String -Attribute Key -Name Path -Description 'Indicates the path to the location of the folder to share.'),
    (New-xDscResourceProperty -Type UInt32 -Attribute Write -Name ConcurrentUserLimit -Description 'Indicates the number of users allowed to concurrently use the share. To set the limit at the maximum number, set this property to zero.'),
    (New-xDscResourceProperty -Type String -Attribute Write -Name Description -Description 'Indicates an optional description for the share.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name FullAccess -Description 'Indicates which accounts are granted Full Control permission to access the share.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name ChangeAccess -Description 'Indicates which accounts are granted Change permission to access the share.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name ReadAccess -Description 'Indicates which accounts are granted Read permission to access the share.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name NoAccess -Description 'Indicates which accounts are denied access to the share.')
)

New-xDscResource -Name $ResourceName -ModuleName $ModuleName -Property $DscResourceProperties -Verbose 

