"""Small-process containment for release tooling that runs untrusted scanners."""

import os
import selectors
import signal
import subprocess
import time


def _kill_process_group(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    process.kill()


def _resource_limiter(memory_limit_bytes, cpu_limit_seconds):
    if os.name != "posix" or (
        memory_limit_bytes is None and cpu_limit_seconds is None
    ):
        return None
    try:
        import resource
    except ImportError:
        return None

    def limit_resources():
        if memory_limit_bytes is not None:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            effective = memory_limit_bytes
            if hard != resource.RLIM_INFINITY:
                effective = min(effective, hard)
            if soft > effective:
                resource.setrlimit(resource.RLIMIT_AS, (effective, hard))
        if cpu_limit_seconds is not None:
            soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
            effective = cpu_limit_seconds
            if hard != resource.RLIM_INFINITY:
                effective = min(effective, hard)
            if soft > effective:
                resource.setrlimit(resource.RLIMIT_CPU, (effective, hard))

    return limit_resources


def run_bounded(
    command,
    *,
    cwd=None,
    env=None,
    timeout,
    max_output_bytes=4 * 1024 * 1024,
    memory_limit_bytes=768 * 1024 * 1024,
    cpu_limit_seconds=None,
):
    """Run a child with bounded time, output, address space, and descendants.

    Output is drained even after its retention cap is reached, so a verbose
    child cannot block on a full pipe. POSIX children start a new process group;
    timeout cleanup kills that group rather than leaving scanner descendants
    attached to the release runner.
    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
        preexec_fn=_resource_limiter(memory_limit_bytes, cpu_limit_seconds),
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    timed_out = False

    def read_available(key):
        try:
            chunk = os.read(key.fileobj.fileno(), 64 * 1024)
        except BlockingIOError:
            return
        if not chunk:
            selector.unregister(key.fileobj)
            key.fileobj.close()
            return
        buffer = captured[key.data]
        if len(buffer) < max_output_bytes:
            buffer.extend(chunk[: max_output_bytes - len(buffer)])

    try:
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(process)
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                read_available(key)
    finally:
        if timed_out:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                process.wait()
        else:
            process.wait()

        # A well-behaved child closes both pipes before the deadline. If a
        # detached descendant ignored the group kill, close our descriptors
        # after a short drain window so cleanup cannot hang the release gate.
        drain_deadline = time.monotonic() + 1
        while selector.get_map() and time.monotonic() < drain_deadline:
            for key, _ in selector.select(0.05):
                read_available(key)
        for key in list(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()
        selector.close()

    stdout = bytes(captured["stdout"])
    stderr = bytes(captured["stderr"])
    if timed_out:
        raise subprocess.TimeoutExpired(
            command, timeout, output=stdout, stderr=stderr
        )
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
