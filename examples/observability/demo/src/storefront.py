"""Storefront handlers — instrumented within the declared contracts.

Note what is where: order ids ride in the event payloads (structured
logs are where high-cardinality facts belong), while the metric carries
only the declared labels method/route/status.
"""


def on_order_placed(order):
    telemetry.event("order.placed", {"order_id": order.id})
    telemetry.metric("storefront_requests_total", {"method": "POST", "route": "/orders", "status": "2xx"})


def on_order_cancelled(order):
    telemetry.event("order.cancelled", {"order_id": order.id})
    telemetry.metric("storefront_requests_total", {"method": "POST", "route": "/orders", "status": "2xx"})
