import pytest

from tools.pay153_checkout import kakao_extractor as kakao


class _FakeResponse:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class _FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return _FakeResponse({"checkout_session_id": "oaics_fixture", "publishable_key": "pk_fixture"})


def test_kakao_init_requires_kakao_pay_and_zero_due():
    payload = {"currency": "krw", "total_summary": {"due": 0}, "payment_method_types": ["card", "kakao_pay"]}
    assert kakao.inspect_kakao_init(payload, "test", require_zero=True) == "0"


def test_kakao_init_rejects_other_provider():
    payload = {"currency": "krw", "total_summary": {"due": 0}, "payment_method_types": ["card"]}
    with pytest.raises(RuntimeError, match="checkout_not_kakao_trial"):
        kakao.inspect_kakao_init(payload, "test", require_zero=True)


def test_kakao_init_allows_nonzero_amount_when_promotion_is_disabled():
    payload = {"currency": "krw", "total_summary": {"due": 9900}, "payment_method_types": ["kakao_pay"]}
    assert kakao.inspect_kakao_init(payload, "test", require_zero=False) == "9900"


def test_kakao_checkout_omits_promotion_when_disabled(monkeypatch):
    monkeypatch.delenv("KAKAO_PROMO_MODE", raising=False)
    session = _FakeSession()

    kakao.create_checkout(session, "access-token", apply_promo=False)

    payload = session.posts[0][1]["json"]
    assert "promo_campaign" not in payload


def test_extract_redirect_walks_nested_setup_intent():
    url = "https://nicepay.example/pay/abc"
    payload = {"setup_intent": {"next_action": {"type": "redirect_to_url", "redirect_to_url": {"url": url}}}}
    assert kakao.extract_redirect(payload) == url


def test_kakao_proxy_chain_preserves_sticky_seed():
    seed = "http://user:pass_country-vn@proxy.example:8080"
    checkout, promotion, provider = kakao.kakao_proxy_chain(seed)
    assert "country-kr" in checkout
    assert "country-vn" in promotion
    assert "country-kr" in provider
    assert kakao.proxy_chain_key(checkout) == kakao.proxy_chain_key(promotion) == kakao.proxy_chain_key(provider)


def test_kakao_proxy_chain_provider_follows_checkout_country():
    seed = "http://user:pass_country-us@proxy.example:8080"
    checkout, promotion, provider = kakao.kakao_proxy_chain(
        seed,
        checkout_country="US",
        promotion_country="KR",
        provider_country="US",
    )
    assert "country-us" in checkout
    assert "country-kr" in promotion
    assert "country-us" in provider
