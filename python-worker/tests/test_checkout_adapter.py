from __future__ import annotations

import unittest
import sys
from types import ModuleType
from unittest.mock import patch

class FakeStore:
    def get(self, _job_id: str, public: bool = False):
        return None


fake_app = ModuleType("app")
fake_app.STORE = FakeStore()
previous_app = sys.modules.get("app")
sys.modules["app"] = fake_app

from tools.pay153_checkout import sunny_adapter

if previous_app is None:
    sys.modules.pop("app", None)
else:
    sys.modules["app"] = previous_app


class CheckoutAdapterTests(unittest.TestCase):
    def test_start_checkout_maps_sunny_pool_names_to_reference_routes(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-3") as create:
            result = sunny_adapter.start_checkout({
                "token": "token",
                "link_type": " PayPal ",
                "checkout_kind": "oaics",
                "checkout_proxies": ["checkout-proxy"],
                "promotion_proxies": ["promotion-proxy"],
            })
        self.assertEqual(result, "job-3")
        options = create.call_args.args[0]
        self.assertEqual(options["link_type"], "paypal")
        self.assertEqual(options["paypal_checkout_mode"], "oaics")
        self.assertTrue(options["oaics_paypal"])
        self.assertTrue(options["named_proxy_pools"])
        self.assertEqual(options["entry_proxies"], ["promotion-proxy"])
        self.assertEqual(options["exit_proxies"], ["checkout-proxy"])

    def test_start_checkout_leaves_non_paypal_routes_on_default_workflow(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-4") as create:
            sunny_adapter.start_checkout({"token": "token", "link_type": "hosted"})

        options = create.call_args.args[0]
        self.assertFalse(options["oaics_paypal"])

    def test_start_checkout_routes_cs_live_paypal_to_reference_workflow(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-cs") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "paypal",
                "checkout_kind": "cs_live",
            })

        options = create.call_args.args[0]
        self.assertEqual(options["paypal_checkout_mode"], "cs_live")
        self.assertFalse(options["oaics_paypal"])

    def test_start_checkout_auto_detects_unknown_paypal_checkout_type(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-auto") as create:
            sunny_adapter.start_checkout({"token": "token", "link_type": "paypal"})

        options = create.call_args.args[0]
        self.assertEqual(options["paypal_checkout_mode"], "auto")
        self.assertTrue(options["oaics_paypal"])

    def test_start_checkout_keeps_pix_checkout_and_promotion_pools_separate(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-5") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "pix",
                "checkout_proxies": ["checkout-proxy"],
                "promotion_proxies": ["promotion-proxy"],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["entry_proxies"], ["promotion-proxy"])
        self.assertEqual(options["exit_proxies"], ["checkout-proxy"])

    def test_start_checkout_routes_gcash_through_single_ph_checkout_pool(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-6") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "gcash",
                "country": "PH",
                "promo_country": "VN",
                "checkout_proxies": ["ph-checkout-proxy"],
                "promotion_proxies": ["vn-promotion-proxy"],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["entry_proxies"], ["ph-checkout-proxy"])
        self.assertEqual(options["exit_proxies"], ["ph-checkout-proxy"])
        self.assertEqual(options["entry_proxy_country"], "PH")
        self.assertEqual(options["exit_proxy_country"], "PH")

    def test_start_checkout_preserves_zero_retry_count(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-zero") as create:
            sunny_adapter.start_checkout({"token": "token", "link_type": "ideal", "retry_count": 0})

        options = create.call_args.args[0]
        self.assertEqual(options["retry_count"], 0)

    def test_start_checkout_defaults_gopay_to_indonesia(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-gopay") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "gopay",
                "checkout_proxies": ["id-checkout-proxy"],
                "promotion_proxies": ["promotion-proxy"],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["country"], "ID")
        self.assertEqual(options["currency"], "IDR")
        self.assertEqual(options["entry_proxies"], ["promotion-proxy"])
        self.assertEqual(options["exit_proxies"], ["id-checkout-proxy"])
        self.assertEqual(options["exit_proxy_country"], "ID")

    def test_start_checkout_defaults_momo_to_vietnam(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-momo") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "momo",
                "checkout_proxies": ["vn-checkout-proxy"],
                "promotion_proxies": ["vn-promotion-proxy"],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["country"], "VN")
        self.assertEqual(options["currency"], "VND")
        self.assertEqual(options["entry_proxy_country"], "VN")
        self.assertEqual(options["exit_proxy_country"], "VN")

    def test_start_checkout_no_promo_reuses_checkout_pool_for_promotion(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-momo-no-promo") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "momo",
                "use_promo": False,
                "checkout_proxies": ["vn-checkout-proxy"],
                "promotion_proxies": [],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["entry_proxies"], ["vn-checkout-proxy"])
        self.assertEqual(options["exit_proxies"], ["vn-checkout-proxy"])
        self.assertFalse(options["use_promo"])

    def test_start_checkout_defaults_blik_to_poland_and_honors_proxy_countries(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-blik") as create:
            sunny_adapter.start_checkout({
                "token": "token",
                "link_type": "blik",
                "country": "DE",
                "promo_country": "NL",
                "currency": "EUR",
                "checkout_proxies": ["de-checkout-proxy"],
                "promotion_proxies": ["nl-promotion-proxy"],
            })

        options = create.call_args.args[0]
        self.assertEqual(options["country"], "PL")
        self.assertEqual(options["currency"], "PLN")
        self.assertEqual(options["entry_proxy_country"], "NL")
        self.assertEqual(options["exit_proxy_country"], "DE")
        self.assertEqual(options["entry_proxies"], ["nl-promotion-proxy"])
        self.assertEqual(options["exit_proxies"], ["de-checkout-proxy"])

    def test_start_checkout_defaults_blik_proxy_countries_to_poland(self) -> None:
        with patch.object(sunny_adapter.STORE, "create", create=True, return_value="job-blik-default") as create:
            sunny_adapter.start_checkout({"token": "token", "link_type": "blik"})

        options = create.call_args.args[0]
        self.assertEqual(options["entry_proxy_country"], "PL")
        self.assertEqual(options["exit_proxy_country"], "PL")

    def test_checkout_status_returns_ordered_sanitized_logs(self) -> None:
        token = "eyJ" + "a" * 80
        job = {
            "status": "running",
            "percent": 50,
            "text": "正在提链",
            "error": "",
            "logs": [
                {"sequence": 41, "time": "10:00:00", "message": f"AT={token}", "major": False},
                {"sequence": 42, "time": "10:00:01", "message": "proxy=socks5://user:pass@127.0.0.1:1080", "major": True},
            ],
            "result": {},
        }

        with patch.object(sunny_adapter.STORE, "get", return_value=job) as get_job:
            result = sunny_adapter.checkout_status("job-1")

        get_job.assert_called_once_with("job-1", public=False)
        self.assertEqual([item["sequence"] for item in result["logs"]], [41, 42])
        self.assertNotIn(token, result["logs"][0]["message"])
        self.assertIn("[TOKEN]", result["logs"][0]["message"])
        self.assertNotIn("user:pass", result["logs"][1]["message"])
        self.assertIn("socks5://[PROXY]@", result["logs"][1]["message"])

    def test_checkout_status_translates_legacy_proxy_pool_labels(self) -> None:
        job = {
            "status": "running",
            "percent": 25,
            "logs": [
                {"message": "代理池 1 用于优惠检查，代理池2用于创建 Checkout"},
            ],
            "result": {},
        }

        with patch.object(sunny_adapter.STORE, "get", return_value=job):
            result = sunny_adapter.checkout_status("job-legacy")

        message = result["logs"][0]["message"]
        self.assertEqual(message, "Promotion代理池 用于优惠检查，Checkout代理池用于创建 Checkout")
        self.assertNotIn("代理池 1", message)
        self.assertNotIn("代理池2", message)

    def test_checkout_status_preserves_reference_result_fields(self) -> None:
        job = {
            "status": "done",
            "percent": 100,
            "text": "提取完成",
            "error": "",
            "logs": [],
            "result": {
                "plan": "plus",
                "account_email": "user@example.com",
                "link_type": "paypal",
                "checkout_session_id": "cs_live_123",
                "checkout_kind": "cs_live",
                "paypal_url": "https://pay.example/approve",
                "payment_methods": ["card", "paypal"],
                "checkout_amount": 0,
                "promo_requested": True,
                "promo_applied": True,
                "country": "US",
                "currency": "USD",
            },
        }
        with patch.object(sunny_adapter.STORE, "get", return_value=job):
            result = sunny_adapter.checkout_status("job-2")
        payload = result["result"]
        self.assertEqual(payload["account_email"], "user@example.com")
        self.assertEqual(payload["checkout_session_id"], "cs_live_123")
        self.assertEqual(payload["checkout_kind"], "cs_live")
        self.assertEqual(payload["paypal_link"], "https://pay.example/approve")
        self.assertEqual(payload["payment_methods"], ["card", "paypal"])
        self.assertTrue(payload["promo_applied"])

    def test_checkout_status_preserves_gopay_midtrans_url(self) -> None:
        midtrans_url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"
        job = {
            "status": "done",
            "percent": 100,
            "text": "GoPay 提取完成",
            "error": "",
            "logs": [],
            "result": {
                "link_type": "gopay",
                "provider_redirect_url": midtrans_url,
                "gopay_midtrans_url": midtrans_url,
            },
        }
        with patch.object(sunny_adapter.STORE, "get", return_value=job):
            result = sunny_adapter.checkout_status("job-gopay")

        self.assertEqual(result["result"]["payment_link"], midtrans_url)
        self.assertEqual(result["result"]["gopay_midtrans_url"], midtrans_url)

    def test_checkout_status_preserves_blik_payment_url(self) -> None:
        blik_url = "https://checkout.stripe.com/c/pay/cs_live_123#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEn"
        job = {
            "status": "done",
            "percent": 100,
            "text": "BLIK 提取完成",
            "error": "",
            "logs": [],
            "result": {
                "link_type": "blik",
                "provider_redirect_url": blik_url,
                "blik_payment_url": blik_url,
            },
        }
        with patch.object(sunny_adapter.STORE, "get", return_value=job):
            result = sunny_adapter.checkout_status("job-blik")

        self.assertEqual(result["result"]["payment_link"], blik_url)
        self.assertEqual(result["result"]["blik_payment_url"], blik_url)


if __name__ == "__main__":
    unittest.main()
