# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import win32api
import win32con
from ctypes.wintypes import DWORD, HANDLE
from ctypes import (
    WinError,
    byref,
    c_void_p,
    sizeof,
)
from contextlib import contextmanager
from typing import Generator, Optional

from ._api import (
    # Constants
    TOKEN_ADJUST_PRIVILEGES,
    LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT,
    PI_NOUI,
    # Structures
    PROFILEINFO,
    SE_BACKUP_NAME,
    SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED,
    SE_RESTORE_NAME,
    TOKEN_PRIVILEGES,
    # Functions
    AdjustTokenPrivileges,
    CloseHandle,
    CreateEnvironmentBlock,
    GetCurrentProcess,
    GetCurrentProcessId,
    LogonUserW,
    LookupPrivilegeValueW,
    LoadUserProfileW,
    OpenProcessToken,
    ProcessIdToSessionId,
    UnloadUserProfile,
)


def get_process_user():
    """
    Returns the user name of the user running the current process.
    """
    return win32api.GetUserNameEx(win32con.NameSamCompatible)


def get_current_process_session_id() -> int:
    """
    Finds the Session ID of the current process, and returns it.
    """
    proc_id = GetCurrentProcessId()
    session_id = DWORD(0)
    # Ignore the return value; will only fail if given a bad
    # process id, and that's clearly impossible here.
    ProcessIdToSessionId(proc_id, byref(session_id))
    return session_id.value


def logon_user(username: str, password: str) -> HANDLE:
    """
    Attempt to logon as the given username & password.
    Return a HANDLE to a logon_token.

    Note:
      The caller *MUST* call CloseHandle on the returned value when done with it.
      Handles are not automatically garbage collected.

    Raises:
        OSError - If an error is encountered.
    """
    hToken = HANDLE(0)
    if not LogonUserW(
        username,
        None,  # TODO - domain handling??
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        byref(hToken),
    ):
        raise WinError()

    return hToken


@contextmanager
def logon_user_context(username: str, password: str) -> Generator[HANDLE, None, None]:
    """
    A context manager wrapper around logon_user(). This will automatically
    Close the logon_token when the context manager is exited.
    """
    hToken: Optional[HANDLE] = None
    try:
        hToken = logon_user(username, password)
        yield hToken
    finally:
        if hToken is not None and not CloseHandle(hToken):
            raise WinError()


def environment_block_for_user(logon_token: HANDLE) -> c_void_p:
    """
    Create an Environment Block for a given logon_token and return it.
    Per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock
    "The environment block is an array of null-terminated Unicode strings. The list ends with two nulls (\0\0)."

    Returns:
        Pointer to the environment block

    Raises:
        OSError - If there is an error creating the block

    Notes:
     1) The returned block *MUST* be deallocated with DestroyEnvironmentBlock when done
     2) Destroying an environment block while it is in use (e.g. while the process it was passed
        to is still running) WILL result in a hard to debug crash in ntdll.dll. So, don't do that!
    """
    environment = c_void_p()
    if not CreateEnvironmentBlock(byref(environment), logon_token, False):
        raise WinError()
    return environment


def adjust_privileges(privilege_constants: list[str], enable: bool) -> None:
    """
    Adjusts the privileges of THIS PROCESS.

    Args:
        privilege_constants: List of the privilege constants to enable/disable.
            See: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
        enable: True if we are to enable the privileges, False if we're to disable them

    Raises:
        OSError - If there is an error modifying the privileges.
    """
    proc_token = HANDLE(0)
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, byref(proc_token)):
        raise WinError()

    token_privileges = TOKEN_PRIVILEGES.allocate(len(privilege_constants))
    privs_array = token_privileges.privileges_array()
    for i, name in enumerate(privilege_constants):
        if not LookupPrivilegeValueW(None, name, byref(privs_array[i].Luid)):
            CloseHandle(proc_token)
            raise WinError()
        privs_array[i].Attributes = SE_PRIVILEGE_ENABLED if enable else SE_PRIVILEGE_REMOVED

    if not AdjustTokenPrivileges(
        proc_token, False, byref(token_privileges), sizeof(token_privileges), None, None
    ):
        CloseHandle(proc_token)
        raise WinError()

    CloseHandle(proc_token)


@contextmanager
def grant_privilege_context(privilege_constants: list[str]) -> Generator[None, None, None]:
    """
    A context wrapper around adjust_privileges().
    This will enable the given privileges when entered, and disable them when exited.
    """
    try:
        adjust_privileges(privilege_constants, True)
        yield
    finally:
        adjust_privileges(privilege_constants, False)


def load_user_profile(user: str, logon_token: HANDLE) -> PROFILEINFO:
    """
    Loads the profile for the given user.

    Args:
        user: The username of the user whose profile we're loading
        logon_token: "Token for the user, which is returned by the LogonUser,
            CreateRestrictedToken, DuplicateToken, OpenProcessToken, or OpenThreadToken
            function. The token must have TOKEN_QUERY, TOKEN_IMPERSONATE, and TOKEN_DUPLICATE access."
            Reference: https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew

    Returns:
        The PROFILEINFO for the loaded profile

    Note:
        The caller MUST UnloadUserProfile the return.hProfile when done with the logon_token, and before
        closing the token.
    """
    # TODO - Handle Roaming Profiles
    # As per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks
    # "Services and applications that call LoadUserProfile should check to see if the user has a roaming profile. ..."

    # "The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges"
    with grant_privilege_context([SE_BACKUP_NAME, SE_RESTORE_NAME]):
        # Note: As per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks
        # the caller must *be* an Administrator or the LocalSystem account.
        pi = PROFILEINFO()
        pi.dwSize = sizeof(PROFILEINFO)
        pi.lpUserName = user
        pi.dwFlags = PI_NOUI  # Prevents displaying of messages

        if not LoadUserProfileW(logon_token, byref(pi)):
            raise WinError()

        return pi


@contextmanager
def user_profile_context(username: str, logon_token: HANDLE) -> Generator[PROFILEINFO, None, None]:
    """
    A context manager around load_user_profile that ensures that the profile is unloaded when done.
    """

    profile_info = load_user_profile(username, logon_token)
    try:
        yield profile_info
    finally:
        return
        if not UnloadUserProfile(logon_token, profile_info.hProfile):
            # "Before calling UnloadUserProfile you should ensure that all handles to keys that you
            # have opened in the user's registry hive are closed. If you do not close all open
            # registry handles, the user's profile fails to unload."
            raise WinError()
