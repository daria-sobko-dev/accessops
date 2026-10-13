"""Ansible stdout callback: print the whole run as one JSON document at the end.

AccessOps parses this output (accessops/linux.py). Only a few safe fields of each task
result are kept: changed/failed/skipped/unreachable flags and the message.
"""

import json

from ansible.plugins.callback import CallbackBase

KEPT_FIELDS = ("changed", "failed", "skipped", "unreachable", "msg", "stderr", "rc")


def _payload(result):
    data = getattr(result, "result", None)
    if data is None:
        data = result._result
    return {key: data[key] for key in KEPT_FIELDS if key in data}


def _host(result):
    host = getattr(result, "host", None) or result._host
    return host.get_name()


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "accessops_json"

    def __init__(self):
        super().__init__()
        self._tasks = []

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._tasks.append({"task": {"name": task.get_name()}, "hosts": {}})

    def _record(self, result, **flags):
        if not self._tasks:
            return
        self._tasks[-1]["hosts"][_host(result)] = _payload(result) | flags

    def v2_runner_on_ok(self, result):
        self._record(result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, failed=not ignore_errors)

    def v2_runner_on_unreachable(self, result):
        self._record(result, unreachable=True)

    def v2_runner_on_skipped(self, result):
        self._record(result, skipped=True)

    def v2_playbook_on_stats(self, stats):
        summary = {host: stats.summarize(host) for host in sorted(stats.processed)}
        output = {"plays": [{"tasks": self._tasks}], "stats": summary}
        self._display.display(json.dumps(output, default=str))
