from dataclasses import dataclass
from typing import Optional
from opensight.core.constants import DEFAULT_PROBE_CONCURRENCY, THEME_KEY_SYSTEM
from opensight.core.database import Repository

@dataclass
class AppSettings:
    theme_preference: str = THEME_KEY_SYSTEM
    probe_concurrency: int = DEFAULT_PROBE_CONCURRENCY
    last_view_mode: str = "综合推荐"
    custom_openvpn_path: Optional[str] = None
    routing_beta_enabled: bool = False
    routing_fail_closed: bool = True

    def validate(self) -> None:
        if self.theme_preference not in ("system", "light", "dark"):
            self.theme_preference = THEME_KEY_SYSTEM
        if not (1 <= self.probe_concurrency <= 12):
            self.probe_concurrency = DEFAULT_PROBE_CONCURRENCY

    @classmethod
    def load_from_repository(cls, repo: Repository) -> "AppSettings":
        s = cls(
            theme_preference=repo.get_setting("theme_preference", THEME_KEY_SYSTEM) or THEME_KEY_SYSTEM,
            probe_concurrency=int(
                repo.get_setting("probe_concurrency", str(DEFAULT_PROBE_CONCURRENCY)) or DEFAULT_PROBE_CONCURRENCY
            ),
            last_view_mode=repo.get_setting("last_view_mode", "综合推荐") or "综合推荐",
            routing_beta_enabled=(repo.get_setting("routing_beta_enabled", "0") == "1"),
        )
        s.validate()
        return s

    def save_to_repository(self, repo: Repository) -> None:
        self.validate()
        repo.set_setting("theme_preference", self.theme_preference)
        repo.set_setting("probe_concurrency", str(self.probe_concurrency))
        repo.set_setting("last_view_mode", self.last_view_mode)
        repo.set_setting("routing_beta_enabled", "1" if self.routing_beta_enabled else "0")
