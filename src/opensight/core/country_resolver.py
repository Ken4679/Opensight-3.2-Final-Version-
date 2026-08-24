from dataclasses import dataclass
import re
from typing import Final, Optional

@dataclass(frozen=True)
class LocationInfo:
    country: str
    country_code: str
    city: str

_COUNTRY_MAP: Final[dict[str, str]] = {
    "JP": "日本", "NL": "荷兰", "US": "美国", "SG": "新加坡",
    "CH": "瑞士", "DE": "德国", "GB": "英国", "UK": "英国",
    "CA": "加拿大", "FR": "法国", "AU": "澳大利亚", "HK": "中国香港",
    "TW": "中国台湾", "KR": "韩国", "SE": "瑞典", "NO": "挪威",
}

_EXPLICIT_CITY_CUES: Final[dict[str, str]] = {
    "tokyo": "Tokyo", "osaka": "Osaka", "amsterdam": "Amsterdam",
    "newyork": "New York", "losangeles": "Los Angeles", "singapore": "Singapore",
    "zurich": "Zurich", "frankfurt": "Frankfurt", "london": "London",
}

class CountryResolver:
    @staticmethod
    def resolve(server_name: str, hostname: Optional[str] = None, filename: Optional[str] = None) -> LocationInfo:
        for text in [server_name or "", hostname or "", filename or ""]:
            clean = text.strip().lower()
            if not clean:
                continue
            m = re.search(r"\b([a-z]{2})[-_]?(free|tor|p2p|plus)?[-_#]?(\d+)?\b", clean)
            if m:
                code = m.group(1).upper()
                if code in _COUNTRY_MAP:
                    return LocationInfo(_COUNTRY_MAP[code], code, CountryResolver._detect_city(clean))
        return LocationInfo("未知国家", "UNKNOWN", "未知城市")

    @staticmethod
    def _detect_city(text: str) -> str:
        lowered = text.lower()
        for cue, city in _EXPLICIT_CITY_CUES.items():
            if cue in lowered:
                return city
        return "未知城市"