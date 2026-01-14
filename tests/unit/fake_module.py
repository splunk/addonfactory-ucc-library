import sys
import types
from collections import namedtuple
from typing import Any, Optional
from unittest.mock import MagicMock


CallerArgs = namedtuple("CallerArgs", ["id", "data"])

ACTION_LIST = 0
ACTION_REMOVE = 1
ACTION_CREATE = 2
ACTION_EDIT = 3


class MConfigHandler:
    def __init__(self, action: int, caller_args: CallerArgs):
        self.requestedAction = action
        self.callerArgs = caller_args

    def handleList(self, confInfo: Any):
        raise NotImplementedError()

    def handleCreate(self, confInfo: Any):
        raise NotImplementedError()

    def handleEdit(self, confInfo: Any):
        raise NotImplementedError()

    def handleRemove(self, confInfo: Any):
        raise NotImplementedError()

    def getSessionKey(self):
        return "abcd"

    @classmethod
    def get(
        cls,
        name: Optional[str] = None,
        caller_args: Optional[dict[str, Any]] = None,
        conf_info: Optional[Any] = None,
    ):
        if caller_args is None:
            caller_args = {}
        if conf_info is None:
            conf_info = MagicMock()
        return cls(ACTION_LIST, CallerArgs(name, caller_args)).handleList(conf_info)


def mock_splunk_module() -> MagicMock:
    sys.modules["splunk"] = types.ModuleType("splunk")

    admin = MagicMock()
    sys.modules["splunk.admin"] = admin

    admin.MConfigHandler = MConfigHandler

    for action in ("ACTION_LIST", "ACTION_REMOVE", "ACTION_CREATE", "ACTION_EDIT"):
        setattr(admin, action, globals()[action])

    return admin
