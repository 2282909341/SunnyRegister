from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable


SentinelFactory = Callable[..., Awaitable[dict[str, str]]]


def resolve_payment_sentinel_headers(
    factory: SentinelFactory,
    proxy: str,
    flow: str,
    device_id: str,
    did: str,
    *,
    use_sen: bool = True,
    use_so: bool = True,
    allow_fallback: bool = False,
    log: Callable[[str], None] = lambda _message: None,
    client_context=None,
    proof_policy=None,
    payment_endpoint=None,
) -> dict[str, str]:
    factory_kwargs = {
        "use_sen": use_sen,
        "use_so": use_so,
    }
    if client_context is not None:
        factory_kwargs["client_context"] = client_context
    if proof_policy is not None:
        factory_kwargs["proof_policy"] = proof_policy
    if payment_endpoint is not None:
        factory_kwargs["payment_endpoint"] = payment_endpoint
    try:
        return asyncio.run(factory(
            proxy, flow, device_id, did, **factory_kwargs,
        ))
    except RuntimeError as exc:
        message = str(exc)
        fallbackable = message.startswith("Sentinel token generation failed") or message.startswith("Sentinel Node VM")
        if not allow_fallback or not fallbackable:
            raise
        log(
            "Sentinel 完整证明因传输/运行时异常未生成，降级为不携带 Sentinel 头继续请求："
            + message.split(":", 1)[-1].strip()[:180]
        )
        return {}
