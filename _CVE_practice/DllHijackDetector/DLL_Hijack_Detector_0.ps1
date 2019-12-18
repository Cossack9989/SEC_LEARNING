if($args.Count -le 0)
{
    Write-Host -foregroundColor Green "Introduction：`r`n    Detecting DLL_HIJACK VULN"
    Write-Host -foregroundColor Green "Usage:`r`n    " $MyInvocation.MyCommand.Definition " c:\app.exe"
    return
}
Write-Host -foregroundColor Green "Getting KnownDLLs RegeditTable..."
$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
$DLLsList = (Get-ItemProperty $RegPath) | Get-Member | Select-Object -Property Name
[System.Collections.ArrayList]$KnownDLLsList = $DLLsList
$KnownDLLsList.Clear()
foreach($item in $DLLsList)
{
    if(($item.Name -ne "Equals") -and ($item.Name -ne "GetHashCode") -and ($item.Name -ne "GetType") -and ($item.Name -ne "ToString") -and 
    ($item.Name -ne "DllDirectory") -and ($item.Name -ne "DllDirectory32") -and ($item.Name -ne "PSChildName") -and ($item.Name -ne "PSDrive") -and 
    ($item.Name -ne "PSParentPath")  -and ($item.Name -ne "PSPath")  -and ($item.Name -ne "PSProvider"))
    {$KnownDLLsList.Add($item.Name.ToUpper()+".DLL") | Out-Null}
}
Write-Host -foregroundColor Green "Getting KnownDLLs Done!!!"

$FilePath = $args[0]
Write-Host -foregroundColor Green "PROC START" $args[0]
$process = [System.Diagnostics.Process]::Start($FilePath)
Write-Host -foregroundColor Green "GET MODULE"
sleep(1)
$modules = $process.Modules | Select-Object -Property ModuleName,FileName
Write-Host -foregroundColor Green "PROC MODULE LOAD"  $modules.Count " sum"
kill $process.Id
$process.WaitForExit()
Write-Host -foregroundColor Green "PROC END"
[System.Collections.ArrayList]$ModulesList = $modules
$ModulesList.RemoveAt(0)
Write-Host -foregroundColor Red "VULN DETECTED!"
foreach($module in $ModulesList)
{
    if(!$KnownDLLsList.Contains($module.ModuleName.ToUpper()))
    {
       "{0,-30}   {1,30}" -f $module.ModuleName, $module.FileName
    }
}
trap
{
    $info = $_.InvocationInfo
    Write-Host -foregroundColor Red $info.ScriptLineNumber $info.OffsetInLine $_.Exception.Message
    return
}
