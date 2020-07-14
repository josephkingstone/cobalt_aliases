# Usage
# 'Service' | Get-ServiceAcl | Select-Object -ExpandProperty Access

Add-Type  @"
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig = 1,
      ChangeConfig = 2,
      QueryStatus = 4,
      EnumerateDependents = 8,
      Start = 16,
      Stop = 32,
      PauseContinue = 64,
      Interrogate = 128,
      UserDefinedControl = 256,
      Delete = 65536,
      ReadControl = 131072,
      WriteDac = 262144,
      WriteOwner = 524288,
      Synchronize = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll = 268435456,
      GenericExecute = 536870912,
      GenericWrite = 1073741824,
      GenericRead = 2147483648
  }
"@
 
function Get-ServiceAcl {
    [CmdletBinding(DefaultParameterSetName="ByName")]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ParameterSetName="ByName")]
        [string[]] $Name,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="ByDisplayName")]
        [string[]] $DisplayName,
        [Parameter(Mandatory=$false, Position=1)]
        [string] $ComputerName = $env:COMPUTERNAME
    )
 
    # If display name was provided, get the actual service name:
    switch ($PSCmdlet.ParameterSetName) {
        "ByDisplayName" {
            $Name = Get-Service -DisplayName $DisplayName -ComputerName $ComputerName -ErrorAction Stop | 
                Select-Object -ExpandProperty Name
        }
    }
 
    # Make sure computer has 'sc.exe':
    $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"
    if (-not $ServiceControlCmd) {
        throw "Could not find $env:SystemRoot\system32\sc.exe command!"
    }
 
    # Get-Service does the work looking up the service the user requested:
    Get-Service -Name $Name | ForEach-Object {
         
        # We might need this info in catch block, so store it to a variable
        $CurrentName = $_.Name
 
        # Get SDDL using sc.exe
        $Sddl = & $ServiceControlCmd.Definition "\\$ComputerName" sdshow "$CurrentName" | Where-Object { $_ }
 
        try {
            # Get the DACL from the SDDL string
            $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
        }
        catch {
            Write-Warning "Couldn't get security descriptor for service '$CurrentName': $Sddl"
            return
        }
 
        # Create the custom object with the note properties
        $CustomObject = New-Object -TypeName PSObject -Property ([ordered] @{ Name = $_.Name
                                                                              Dacl = $Dacl
                                                                            })
 
        # Add the 'Access' property:
        $CustomObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
            $this.Dacl.DiscretionaryAcl | ForEach-Object {
                $CurrentDacl = $_
 
                try {
                    $IdentityReference = $CurrentDacl.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
                }
                catch {
                    $IdentityReference = $CurrentDacl.SecurityIdentifier.Value
                }
                 
                New-Object -TypeName PSObject -Property ([ordered] @{ 
                                ServiceRights = [ServiceAccessFlags] $CurrentDacl.AccessMask
                                AccessControlType = $CurrentDacl.AceType
                                IdentityReference = $IdentityReference
                                IsInherited = $CurrentDacl.IsInherited
                                InheritanceFlags = $CurrentDacl.InheritanceFlags
                                PropagationFlags = $CurrentDacl.PropagationFlags
                                                                    })
            }
        }
 
        # Add 'AccessToString' property that mimics a property of the same name from normal Get-Acl call
        $CustomObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
            $this.Access | ForEach-Object {
                "{0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.ServiceRights
            } | Out-String
        }
 
        $CustomObject
    }
}
