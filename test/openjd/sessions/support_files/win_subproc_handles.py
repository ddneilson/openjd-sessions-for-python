# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Introspects this process to find the handles that it has inherited from its
# parent process.
# Per MS support, the way to accomplish this is with undocumented functionality of the
# NtQueryProcessInformation API.
# That API can be used to obtain a list of all of a process' handles that are
# marked for inheritence. So, you fetch the marked-inheritance handles from both
# this process and the parent process. The handle IDs that appear in both lists
# are the ones that have been inherited to this process from its parent.
#
# Warning: NtQueryProcessInformation is an "undocumented API" and thus its
# functionality and the layout of its datastructures can change between Windows
# versions.

import ctypes
from ctypes import (
    POINTER,
    c_ulong,
    c_ulonglong,
    c_void_p,
)
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LONG,
    PULONG,
)
from collections.abc import Sequence


# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L163
ProcessBasicInformation = 0
ProcessHandleCount = 20
ProcessHandleInformation = 51

# Ref: https://ntdoc.m417z.com/process_handle_table_entry_info#handleattributes
OBJ_PROTECT_CLOSE = 0x01
OBJ_INHERIT = 0x02
OBJ_PERMANENT = 0x04
OBJ_EXCLUSIVE = 0x08

# https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
PROCESS_QUERY_INFORMATION = 0x0400


# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("ExitStatus", c_ulong),
        ("PebBaseAddress", c_void_p),
        ("AffinityMask", c_ulonglong),
        ("BasePriority", DWORD),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
    )


# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L643
class PROCESS_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = (
        ("HandleValue", HANDLE),
        ("HandleCount", c_ulonglong),
        ("PointerCount", c_ulonglong),
        ("GrantedAccess", c_ulong),
        ("ObjectTypeIndex", c_ulong),
        ("HandleAttributes", c_ulong),
        ("Reserved", c_ulong),
    )


# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L654
class PROCESS_HANDLE_SNAPSHOT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("NumberOfHandles", c_ulonglong),
        ("Reserved", c_ulonglong),
        ("Handles", PROCESS_HANDLE_TABLE_ENTRY_INFO * 0),
    )

    @staticmethod
    def allocate_bytes(bytes: int) -> "PROCESS_HANDLE_SNAPSHOT_INFORMATION":
        malloc_buffer = (ctypes.c_byte * bytes)()
        to_return = ctypes.cast(malloc_buffer, POINTER(PROCESS_HANDLE_SNAPSHOT_INFORMATION))[0]
        to_return.NumberOfHandles = 0
        return to_return

    @staticmethod
    def allocate(length: int) -> "PROCESS_HANDLE_SNAPSHOT_INFORMATION":
        malloc_size_in_bytes = ctypes.sizeof(
            PROCESS_HANDLE_SNAPSHOT_INFORMATION
        ) + 2 * ctypes.sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO)
        malloc_buffer = (ctypes.c_byte * malloc_size_in_bytes)()
        to_return = ctypes.cast(malloc_buffer, POINTER(PROCESS_HANDLE_SNAPSHOT_INFORMATION))[0]
        to_return.NumberOfHandles = length
        return to_return

    def handles_array(self) -> Sequence[PROCESS_HANDLE_TABLE_ENTRY_INFO]:
        return ctypes.cast(
            ctypes.byref(self.Handles),
            ctypes.POINTER(PROCESS_HANDLE_TABLE_ENTRY_INFO * self.NumberOfHandles),
        ).contents


kernel32 = ctypes.WinDLL("kernel32")
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcess.argtypes = []
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid
kernel32.GetProcessId.restype = DWORD
kernel32.GetProcessId.argtypes = [
    HANDLE,  # [in] Process
]
# https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]  # [in] hObject
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
kernel32.OpenProcess.restype = HANDLE
kernel32.OpenProcess.argtypes = [
    DWORD,  # [in] dwDesiredAccess
    BOOL,  # [in] bInheritHandle
    DWORD,  # [in] dwProcessId
]
CloseHandle = kernel32.CloseHandle
GetCurrentProcess = kernel32.GetCurrentProcess
GetProcessId = kernel32.GetProcessId
OpenProcess = kernel32.OpenProcess

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
ntdll = ctypes.WinDLL("ntdll")
ntdll.NtQueryInformationProcess.restype = LONG
ntdll.NtQueryInformationProcess.argtypes = [
    HANDLE,  # [in] ProcessHandle
    DWORD,  # [in] ProcessInformationClass (actually an enum)
    c_void_p,  # [out] ProcessInformation
    c_ulong,  # [in] ProcessInformationLength
    PULONG,  # [out, optional] ReturnLength
]
NtQueryInformationProcess = ntdll.NtQueryInformationProcess


def _get_inherit_handles_for(proc_handle: HANDLE) -> set[HANDLE]:
    desired_size = c_ulong(0)
    actual_size = c_ulong(0)
    buffer = (ctypes.c_byte * 16)()
    # Query the first time to discover how large the return buffer needs to be
    ret = NtQueryInformationProcess(
        proc_handle, ProcessHandleInformation, ctypes.byref(buffer), 16, ctypes.byref(desired_size)
    )

    snapshot = PROCESS_HANDLE_SNAPSHOT_INFORMATION.allocate_bytes(desired_size.value)
    # Query to get the actual data
    ret = NtQueryInformationProcess(
        proc_handle,
        ProcessHandleInformation,
        ctypes.byref(snapshot),
        desired_size.value,
        ctypes.byref(actual_size),
    )

    if ret == 0:
        handles = set[HANDLE]()
        handles_arr = snapshot.handles_array()
        for h in handles_arr:
            if not h.HandleValue:
                continue
            if h.HandleAttributes & OBJ_INHERIT:
                handles.add(h.HandleValue)
        return handles
    else:
        raise ctypes.WinError()


def get_inherited_handles(child_pid: int) -> tuple[set[HANDLE],set[HANDLE]]:
    """Compare the handles of our process against those of the child process with
    the given PID (Process ID). Return the set of handles that have been inherited
    from us by the child process.
    """
    ph = GetCurrentProcess()

    cph = OpenProcess(PROCESS_QUERY_INFORMATION, False, child_pid)
    if cph is None:
        raise ctypes.WinError()

    self_inherited_handles = _get_inherit_handles_for(ph)
    child_inherited_handles = _get_inherit_handles_for(cph)

    CloseHandle(ph)
    CloseHandle(cph)

    return self_inherited_handles, child_inherited_handles
    handles_inherited_from_parent = self_inherited_handles & child_inherited_handles

    print("Self Handles with Inherit bit set:", ", ".join(hex(h) for h in self_inherited_handles))
    print("Child Handles with Inherit bit set:", ", ".join(hex(h) for h in child_inherited_handles))
    print("Inherited from parent:", ", ".join(hex(h) for h in handles_inherited_from_parent))
    print("Total inherited handles:", len(handles_inherited_from_parent))

    return handles_inherited_from_parent
