from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sunny_core.account_persona import (
    AccountPersona,
    country_locale,
    normalize_persona_country,
    pick_persona,
)
from sunny_core.fingerprint_pool import impersonate_pool, pick_impersonate
from sunny_core.proxy import normalize_proxy_url, sticky_proxy_url
from sunny_core.sentinel import SentinelTokenGenerator


PROXY_WITH_USER = "http://user123:pa%40ss@us.rrp.bestgo.work:10000"


class AccountPersonaTests(unittest.TestCase):
    def test_persona_is_deterministic_per_seed(self) -> None:
        first = pick_persona("acct@example.com", "JP")
        second = pick_persona("acct@example.com", "JP")
        self.assertEqual(first, second)

    def test_persona_impersonate_matches_fingerprint_pool(self) -> None:
        for seed in ("a@x.com", "b@y.com", "", "seed-3"):
            self.assertEqual(pick_persona(seed, "VN").impersonate, pick_impersonate(seed))
        self.assertIn(pick_persona("a@x.com").impersonate, impersonate_pool())

    def test_country_changes_locale_not_fingerprint(self) -> None:
        jp = pick_persona("acct@example.com", "JP")
        vn = pick_persona("acct@example.com", "VN")
        self.assertEqual(jp.impersonate, vn.impersonate)
        self.assertEqual(jp.user_agent, vn.user_agent)
        self.assertEqual((jp.locale, jp.timezone), ("ja-JP", "Asia/Tokyo"))
        self.assertEqual((vn.locale, vn.timezone), ("vi-VN", "Asia/Ho_Chi_Minh"))
        self.assertEqual(vn.languages, ("vi-VN", "vi"))

    def test_unknown_or_empty_country_falls_back_to_jp(self) -> None:
        self.assertEqual(normalize_persona_country(""), "JP")
        self.assertEqual(normalize_persona_country("ZZ"), "JP")
        self.assertEqual(normalize_persona_country("vn"), "VN")
        self.assertEqual(country_locale(""), ("ja-JP", "ja", "Asia/Tokyo"))

    def test_user_agent_matches_impersonate_family(self) -> None:
        for target in impersonate_pool():
            persona = AccountPersona(
                impersonate=target,
                user_agent="",
                locale="ja-JP",
                languages=("ja-JP", "ja"),
                timezone="Asia/Tokyo",
                screen_width=1920,
                screen_height=1080,
                hardware_concurrency=8,
                device_memory=8,
                platform="Win32",
            )
            # Build a real persona for this target by faking the seed mapping:
            # pick over many seeds until this target appears.
            for index in range(500):
                candidate = pick_persona(f"seed-{target}-{index}", "JP")
                if candidate.impersonate != target:
                    continue
                persona = candidate
                break
            self.assertEqual(persona.impersonate, target)
            ua = persona.user_agent
            if target.startswith("chrome"):
                self.assertIn("Chrome/", ua)
                self.assertIn("Windows NT 10.0", ua)
                self.assertEqual(persona.platform, "Win32")
                self.assertTrue(persona.is_chromium_family)
                self.assertIn(f'"Google Chrome";v="', persona.sec_ch_ua)
            elif target == "edge101":
                self.assertIn("Edg/101", ua)
                self.assertTrue(persona.is_chromium_family)
            elif target.startswith("firefox"):
                self.assertIn("Firefox/", ua)
                self.assertFalse(persona.is_chromium_family)
                self.assertEqual(persona.sec_ch_ua, "")
            else:
                self.assertIn("Macintosh", ua)
                self.assertEqual(persona.platform, "MacIntel")
                self.assertFalse(persona.is_chromium_family)

    def test_accept_language_shape(self) -> None:
        jp = pick_persona("acct@example.com", "JP")
        self.assertEqual(jp.accept_language, "ja-JP,ja;q=0.9,en;q=0.7")
        self.assertEqual(jp.sentinel_languages, "ja-JP,ja")

    def test_screen_and_hardware_are_stable_and_realistic(self) -> None:
        persona = pick_persona("stable@example.com", "US")
        again = pick_persona("stable@example.com", "US")
        self.assertEqual((persona.screen_width, persona.screen_height), (again.screen_width, again.screen_height))
        self.assertEqual(persona.hardware_concurrency, again.hardware_concurrency)
        self.assertIn((persona.screen_width, persona.screen_height), ((1920, 1080), (1680, 1050), (1600, 900), (1536, 864), (1440, 900), (1366, 768), (2560, 1440), (1512, 982), (1728, 1117)))
        self.assertIn(persona.hardware_concurrency, (4, 6, 8, 12, 16))

    def test_persona_spreads_across_pool(self) -> None:
        targets = {pick_persona(f"spread-{index}@example.com", "JP").impersonate for index in range(120)}
        self.assertGreaterEqual(len(targets), 6)


class SentinelPersonaTests(unittest.TestCase):
    def test_sentinel_config_uses_persona(self) -> None:
        persona = pick_persona("sentinel@example.com", "VN")
        generator = SentinelTokenGenerator("device-1", persona.user_agent, persona=persona)
        config = generator._config()
        self.assertEqual(config[0], persona.screen)
        self.assertEqual(config[4], persona.user_agent)
        self.assertEqual(config[8], persona.locale)
        self.assertEqual(config[9], persona.sentinel_languages)

    def test_sentinel_config_defaults_without_persona(self) -> None:
        generator = SentinelTokenGenerator("device-1", "UA-STRING")
        config = generator._config()
        self.assertEqual(config[0], "1920x1080")
        self.assertEqual(config[8], "ja-JP")
        self.assertEqual(config[9], "ja-JP,ja")


class OpenAIHeaderPersonaTests(unittest.TestCase):
    def test_browser_headers_follow_chrome_persona(self) -> None:
        from sunny_core.openai_auth import openai_browser_headers

        for index in range(200):
            persona = pick_persona(f"hdr-{index}@example.com", "JP")
            if not persona.is_chromium_family:
                continue
            headers = openai_browser_headers(persona=persona)
            self.assertEqual(headers["user-agent"], persona.user_agent)
            self.assertEqual(headers["accept-language"], persona.accept_language)
            self.assertEqual(headers["sec-ch-ua"], persona.sec_ch_ua)
            self.assertEqual(headers["sec-ch-ua-platform"], persona.sec_ch_ua_platform)
            return
        self.fail("no chromium persona found in 200 seeds")

    def test_browser_headers_drop_chromium_hints_for_firefox(self) -> None:
        from sunny_core.openai_auth import openai_browser_headers

        for index in range(200):
            persona = pick_persona(f"ff-{index}@example.com", "JP")
            if persona.impersonate.startswith("firefox"):
                headers = openai_browser_headers(persona=persona)
                self.assertEqual(headers["user-agent"], persona.user_agent)
                for key in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
                    self.assertNotIn(key, headers)
                return
        self.fail("no firefox persona found in 200 seeds")

    def test_register_fingerprint_follows_country(self) -> None:
        from sunny_core.openai_auth import device_fingerprint_from_persona, generate_register_fingerprint

        vn = generate_register_fingerprint("VN")
        self.assertEqual(vn.locale, "vi-VN")
        self.assertEqual(vn.timezone, "Asia/Ho_Chi_Minh")
        default = generate_register_fingerprint()
        self.assertEqual(default.locale, "ja-JP")
        persona = pick_persona("fp@example.com", "VN")
        aligned = device_fingerprint_from_persona(persona)
        self.assertEqual(aligned.user_agent, persona.user_agent)
        self.assertEqual(aligned.locale, persona.locale)
        self.assertEqual(aligned.screen_width, persona.screen_width)
        self.assertEqual(aligned.platform, persona.platform)


class StickyProxyUrlTests(unittest.TestCase):
    def setUp(self) -> None:
        # Sticky pinning is opt-in (SUNNY_PROXY_STICKY default off); enable it
        # explicitly for these positive cases.
        self._sticky_patch = patch.dict(os.environ, {"SUNNY_PROXY_STICKY": "1"})
        self._sticky_patch.start()

    def tearDown(self) -> None:
        self._sticky_patch.stop()

    def test_appends_session_suffix_for_account_key(self) -> None:
        sticky = sticky_proxy_url(PROXY_WITH_USER, "acct@example.com")
        self.assertNotEqual(sticky, PROXY_WITH_USER)
        self.assertIn("-session-", sticky)
        self.assertTrue(sticky.startswith("http://user123-session-"))
        self.assertIn(":pa%40ss@us.rrp.bestgo.work:10000", sticky)
        self.assertEqual(normalize_proxy_url(sticky), sticky)

    def test_suffix_is_stable_and_idempotent(self) -> None:
        first = sticky_proxy_url(PROXY_WITH_USER, "acct@example.com")
        second = sticky_proxy_url(PROXY_WITH_USER, "acct@example.com")
        self.assertEqual(first, second)
        again = sticky_proxy_url(first, "acct@example.com")
        self.assertEqual(again, first)
        different = sticky_proxy_url(PROXY_WITH_USER, "other@example.com")
        self.assertNotEqual(different, first)

    def test_no_username_or_empty_key_unchanged(self) -> None:
        self.assertEqual(sticky_proxy_url("http://us.rrp.bestgo.work:10000", "acct@example.com"), "http://us.rrp.bestgo.work:10000")
        self.assertEqual(sticky_proxy_url(PROXY_WITH_USER, ""), PROXY_WITH_USER)
        self.assertEqual(sticky_proxy_url("", "acct@example.com"), "")

    def test_env_flag_disables_stickiness(self) -> None:
        with patch.dict(os.environ, {"SUNNY_PROXY_STICKY": "0"}):
            self.assertEqual(sticky_proxy_url(PROXY_WITH_USER, "acct@example.com"), PROXY_WITH_USER)


if __name__ == "__main__":
    unittest.main()
