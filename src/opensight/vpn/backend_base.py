from abc import ABC, abstractmethod
from typing import Callable, Optional
from opensight.core.models import LogicalNode, Endpoint
from opensight.vpn.credentials import OpenVPNCredentials

class VPNBackend(ABC):
    @abstractmethod
    def connect(
        self,
        node: LogicalNode,
        endpoint: Endpoint,
        profile_path: str,
        credentials: Optional[OpenVPNCredentials] = None,
        on_state_change: Optional[Callable[[str, str], None]] = None,
    ) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        pass

    @abstractmethod
    def get_state(self) -> str:
        pass
