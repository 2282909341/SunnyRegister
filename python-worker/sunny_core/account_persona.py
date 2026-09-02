"""Per-account device persona: impersonate + UA + locale + screen, aligned.

7f82221 already randomized the TLS impersonate target per account. Three
signals still betrayed the batch on every account:

1. Sentinel proofs carried a fixed 1920x1080 screen, a fixed ja-JP locale and
   a hardcoded Chrome 136 user agent that contradicted the randomly picked
   TLS fingerprint.
2. accept-language / browser locale / timezone were pinned to ja-JP even when
   the account egressed through a VN (or other country) proxy, an IP-geography
   contradiction OpenAI can trivially score.
3. Protocol headers, sentinel device payloads and the fallback Camoufox
   fingerprint each used a *different* UA/locale for the same account.

This module derives ONE deterministic persona per seed (account email) and one
locale bundle per proxy country, so the same account presents the same UA,
locale, timezone and screen everywhere, and a JP/VN proxy gets a JP/VN locale.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .fingerprint_pool import pick_impersonate

# Country -> (locale, primary language, timezone). Unknown/empty countries fall
# back to the historical ja-JP profile so previously registered JP accounts keep
# a consistent persona after this change.
_COUNTRY_LOCALES: dict[str, tuple[str, str, str]] = {
    "JP": ("ja-JP", "ja", "Asia/Tokyo"),
    "VN": ("vi-VN", "vi", "Asia/Ho_Chi_Minh"),
    "US": ("en-US", "en", "America/New_York"),
    "CA": ("en-CA", "en", "America/Toronto"),
    "GB": ("en-GB", "en", "Europe/London"),
    "AU": ("en-AU", "en", "Australia/Sydney"),
    "NZ": ("en-NZ", "en", "Pacific/Auckland"),
    "SG": ("en-SG", "en", "Asia/Singapore"),
    "MY": ("ms-MY", "ms", "Asia/Kuala_Lumpur"),
    "TH": ("th-TH", "th", "Asia/Bangkok"),
    "ID": ("id-ID", "id", "Asia/Jakarta"),
    "PH": ("en-PH", "en", "Asia/Manila"),
    "IN": ("en-IN", "en", "Asia/Kolkata"),
    "KR": ("ko-KR", "ko", "Asia/Seoul"),
    "DE": ("de-DE", "de", "Europe/Berlin"),
    "FR": ("fr-FR", "fr", "Europe/Paris"),
    "NL": ("nl-NL", "nl", "Europe/Amsterdam"),
    "ES": ("es-ES", "es", "Europe/Madrid"),
    "IT": ("it-IT", "it", "Europe/Rome"),
    "PL": ("pl-PL", "pl", "Europe/Warsaw"),
    "PT": ("pt-PT", "pt", "Europe/Lisbon"),
    "BR": ("pt-BR", "pt", "America/Sao_Paulo"),
    "MX": ("es-MX", "es", "America/Mexico_City"),
    "TR": ("tr-TR", "tr", "Europe/Istanbul"),
    "HK": ("zh-HK", "zh", "Asia/Hong_Kong"),
    "TW": ("zh-TW", "zh", "Asia/Taipei"),
    "MO": ("zh-MO", "zh", "Asia/Macau"),
}
_DEFAULT_COUNTRY = "JP"

_WINDOWS_SCREENS = ((1920, 1080), (1680, 1050), (1600, 900), (1536, 864), (1440, 900), (1366, 768), (2560, 1440))
_MAC_SCREENS = ((1920, 1080), (1680, 1050), (1440, 900), (1512, 982), (1728, 1117))
_HARDWARE_CONCURRENCY = (4, 6, 8, 12, 16)
_DEVICE_MEMORY = (4, 8, 16)

_CHROME_VERSIONS = {
    "chrome124": 124,
    "chrome131": 131,
    "chrome136": 136,
    "chrome142": 142,
    "chrome145": 145,
}
_FIREFOX_VERSIONS = {
    "firefox133": 133,
    "firefox135": 135,
    "firefox144": 144,
    "firefox147": 147,
}
_SAFARI_VERSIONS = {
    "safari17_0": 17,
    "safari18_0": 18,
}


def normalize_persona_country(country: str = "") -> str:
    code = str(country or "").strip().upper()
    return code if code in _COUNTRY_LOCALES else _DEFAULT_COUNTRY


def country_locale(country: str = "") -> tuple[str, str, str]:
    """Return (locale, primary_language, timezone) for a proxy country code."""
    return _COUNTRY_LOCALES[normalize_persona_country(country)]


@dataclass(frozen=True)
class AccountPersona:
    """One stable device identity for one account across all flows."""

    impersonate: str
    user_agent: str
    locale: str
    languages: tuple[str, ...]
    timezone: str
    screen_width: int
    screen_height: int
    hardware_concurrency: int
    device_memory: int
    platform: str

    @property
    def screen(self) -> str:
        return f"{self.screen_width}x{self.screen_height}"

    @property
    def accept_language(self) -> str:
        # Mirrors the historical protocol header shape: locale, primary with
        # q=0.9, then English as the secondary language.
        return f"{self.locale},{self.languages[1]};q=0.9,en;q=0.7" if len(self.languages) > 1 else f"{self.locale},en;q=0.7"

    @property
    def sentinel_languages(self) -> str:
        # Sentinel config[9] / Node VM "languages" field shape ("ja-JP,ja").
        return ",".join(self.languages)

    @property
    def is_chromium_family(self) -> bool:
        return self.impersonate in _CHROME_VERSIONS or self.impersonate == "edge101"

    @property
    def sec_ch_ua(self) -> str:
        if not self.is_chromium_family:
            return ""
        if self.impersonate == "edge101":
            return '"Microsoft Edge";v="101", "Chromium";v="101", "Not.A/Brand";v="24"'
        version = str(_CHROME_VERSIONS.get(self.impersonate, 136))
        return f'"Google Chrome";v="{version}", "Chromium";v="{version}", "Not.A/Brand";v="24"'

    @property
    def sec_ch_ua_full_version_list(self) -> str:
        if not self.is_chromium_family:
            return ""
        if self.impersonate == "edge101":
            return '"Microsoft Edge";v="101.0.1210.53", "Chromium";v="101.0.1210.53", "Not.A/Brand";v="24.0.0.0"'
        version = f"{_CHROME_VERSIONS.get(self.impersonate, 136)}.0.0.0"
        return f'"Google Chrome";v="{version}", "Chromium";v="{version}", "Not.A/Brand";v="24.0.0.0"'

    @property
    def sec_ch_ua_platform(self) -> str:
        return '"macOS"' if self.platform == "MacIntel" else '"Windows"'

    @property
    def sec_ch_ua_platform_version(self) -> str:
        return '"10.15.7"' if self.platform == "MacIntel" else '"15.0.0"'


def _user_agent_for(impersonate: str) -> tuple[str, str]:
    """Return (user_agent, navigator_platform) for an impersonate target."""
    if impersonate in _CHROME_VERSIONS:
        version = _CHROME_VERSIONS[impersonate]
        return (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
            "Win32",
        )
    if impersonate == "edge101":
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 Edg/101.0.4951.67",
            "Win32",
        )
    if impersonate in _FIREFOX_VERSIONS:
        version = _FIREFOX_VERSIONS[impersonate]
        return (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",
            "Win32",
        )
    if impersonate in _SAFARI_VERSIONS:
        version = _SAFARI_VERSIONS[impersonate]
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.0 Safari/605.1.15",
            "MacIntel",
        )
    # Unknown target: fall back to the generic Chrome 136 Windows profile.
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Win32",
    )


def pick_persona(seed: str = "", country: str = "") -> AccountPersona:
    """Derive the deterministic persona for ``seed`` (account email).

    The impersonate target is delegated to fingerprint_pool.pick_impersonate so
    TLS stays stable per account. Screen / hardware / memory are seeded from the
    same digest. The locale bundle follows the proxy country (default JP, which
    matches the pre-persona registration history).
    """
    seed = str(seed or "")
    normalized_country = normalize_persona_country(country)
    locale, language, timezone = _COUNTRY_LOCALES[normalized_country]
    impersonate = pick_impersonate(seed)
    user_agent, platform = _user_agent_for(impersonate)
    digest = hashlib.sha256((seed or "default").encode("utf-8")).hexdigest()
    screens = _MAC_SCREENS if platform == "MacIntel" else _WINDOWS_SCREENS
    screen = screens[int(digest[:8], 16) % len(screens)]
    hardware = _HARDWARE_CONCURRENCY[int(digest[8:12], 16) % len(_HARDWARE_CONCURRENCY)]
    memory = _DEVICE_MEMORY[int(digest[12:16], 16) % len(_DEVICE_MEMORY)]
    return AccountPersona(
        impersonate=impersonate,
        user_agent=user_agent,
        locale=locale,
        languages=(locale, language),
        timezone=timezone,
        screen_width=int(screen[0]),
        screen_height=int(screen[1]),
        hardware_concurrency=int(hardware),
        device_memory=int(memory),
        platform=platform,
    )
