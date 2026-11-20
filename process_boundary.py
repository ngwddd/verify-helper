"""Process lifetime containment for verification workers."""
from __future__ import annotations

import os
import subprocess
import uuid
from contextlib import contextmanager


@contextmanager
def contain_worker(worker: subprocess.Popen):
    """On Windows, close the dedicated Job Object to end all worker descendants."""
    if os.name != "nt":
        yield "process"
        return

    import win32api
    import win32con
    import win32job

    try:
        job = win32job.CreateJobObject(None, "VerifyHelper-" + uuid.uuid4().hex)
    except win32api.error as error:
        worker.kill()
        raise OSError("Windows Job Object could not be created") from error
    try:
        try:
            limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
            access = win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE
            process = win32api.OpenProcess(access, False, worker.pid)
            try:
                win32job.AssignProcessToJobObject(job, process)
            finally:
                process.Close()
        except win32api.error as error:
            worker.kill()
            raise OSError("Windows Job Object containment could not be established") from error
        yield "windows-job"
    finally:
        job.Close()
