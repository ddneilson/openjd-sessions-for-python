# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import os
import sys
from typing import Any, Optional
import ctypes
from subprocess import list2cmdline, Popen
from subprocess import Handle  # type: ignore # linter doesn't know it exists
import platform
from ._api import (
    # Constants
    LOGON_WITH_PROFILE,
    STARTF_USESTDHANDLES,
    # Structures
    PROCESS_INFORMATION,
    STARTUPINFO,
    # Functions
    CloseHandle,
    CreateProcessAsUserW,
    CreateProcessWithLogonW,
    # DestroyEnvironmentBlock,
)
from ._helpers import environment_block_for_user, logon_user_context
from .._session_user import WindowsSessionUser

# Tell type checker to ignore on non-windows platforms
assert sys.platform == "win32"

if platform.python_implementation() != "CPython":
    raise RuntimeError(
        f"Not compatible with the {platform.python_implementation} of Python. Please use CPython."
    )

CREATE_UNICODE_ENVIRONMENT = 0x400


class PopenWindowsAsUser(Popen):
    """Class to run a process as another user on Windows.
    Derived from Popen, it defines the _execute_child() method to call CreateProcessWithLogonW.
    """

    def __init__(self, user: WindowsSessionUser, *args: Any, **kwargs: Any):
        """
        Arguments:
            username (str):  Name of user to run subprocess as
            password (str):  Password for username
            args (Any):  Popen constructor args
            kwargs (Any):  Popen constructor kwargs
            https://docs.python.org/3/library/subprocess.html#popen-constructor
        """
        self.user = user
        self._env_ptr: Optional[ctypes.c_void_p] = None
        super(PopenWindowsAsUser, self).__init__(*args, **kwargs)

    def __del__(self) -> None:
        # TODO - Doing this destroy causes test runners to start dieing
        # Windows fatal exception: code 0xc0000374
        # ...
        # Current thread 0x00001470 (most recent call first):
        #   File "C:\Users\Administrator\GitHub\openjd-sessions-for-python\src\openjd\sessions\_win32\_popen_as_user.py", line 56 in __del__
        #   File "<shim>", line ??? in <interpreter trampoline>
        #   ...
        #
        # if self._env_ptr is not None:
        #     DestroyEnvironmentBlock(self._env_ptr)
        super().__del__()

    def _execute_child(
        self,
        args,
        executable,
        preexec_fn,
        close_fds,
        pass_fds,
        cwd,
        env,
        startupinfo,
        creationflags,
        shell,
        p2cread,
        p2cwrite,
        c2pread,
        c2pwrite,
        errread,
        errwrite,
        restore_signals,
        start_new_session,
        *additional_args,
        **kwargs,
    ):
        """Execute program (MS Windows version).
        Calls CreateProcessWithLogonW to run a process as another user.
        """

        assert not pass_fds, "pass_fds not supported on Windows."

        commandline = args if isinstance(args, str) else list2cmdline(args)
        # CreateProcess* may modify the commandline, so copy it to a mutable buffer
        cmdline = ctypes.create_unicode_buffer(commandline)

        if executable is not None:
            executable = os.fsdecode(executable)

        if cwd is not None:
            cwd = os.fsdecode(cwd)

        # Initialize structures
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()

        use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
        if use_std_handles:
            si.hStdInput = int(p2cread)
            si.hStdOutput = int(c2pwrite)
            si.hStdError = int(errwrite)
            si.dwFlags |= STARTF_USESTDHANDLES

        sys.audit("subprocess.Popen", executable, args, cwd, env, self.user.user)

        try:
            if self.user.password is not None:
                with logon_user_context(self.user.user, self.user.password) as logon_token:
                    self._env_ptr = environment_block_for_user(logon_token)
                # TODO: Merge the given env into the environment block when env != None.

                # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
                if not CreateProcessWithLogonW(
                    self.user.user,
                    None,  # TODO: Domains not yet supported
                    self.user.password,
                    LOGON_WITH_PROFILE,
                    executable,
                    cmdline,
                    creationflags | CREATE_UNICODE_ENVIRONMENT,
                    self._env_ptr,
                    cwd,
                    ctypes.byref(si),
                    ctypes.byref(pi),
                ):
                    # Raises: OSError
                    raise ctypes.WinError()
            elif self.user.logon_token is not None:
                # From https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
                # If the lpEnvironment parameter is NULL, the new process inherits the environment of the calling process.
                # CreateProcessAsUser does not automatically modify the environment block to include environment variables specific to
                # the user represented by hToken. For example, the USERNAME and USERDOMAIN variables are inherited from the calling
                # process if lpEnvironment is NULL. It is your responsibility to prepare the environment block for the new process and
                # specify it in lpEnvironment.

                self._env_ptr = environment_block_for_user(self.user.logon_token)
                # TODO: Merge the given env into the environment block when env != None.

                if not CreateProcessAsUserW(
                    self.user.logon_token,
                    executable,
                    cmdline,
                    None,
                    None,
                    True,
                    creationflags | CREATE_UNICODE_ENVIRONMENT,
                    self._env_ptr,
                    cwd,
                    ctypes.byref(si),
                    ctypes.byref(pi),
                ):
                    # Raises: OSError
                    raise ctypes.WinError()
            else:
                raise NotImplementedError("Unexpected case for WindowsSessionUser properties")
        finally:
            # Child is launched. Close the parent's copy of those pipe
            # handles that only the child should have open.
            self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)

        # Retain the process handle, but close the thread handle
        CloseHandle(pi.hThread)

        self._child_created = True
        self.pid = pi.dwProcessId
        self._handle = Handle(pi.hProcess)
