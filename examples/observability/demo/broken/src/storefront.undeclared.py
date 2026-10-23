"""The label-accretion regression: order_id rides as a metric label.

The order id belongs in the event payload (see storefront.py); as a
metric label it breeds unbounded cardinality. The linter must catch
this at PR time with the file and line cited.
"""


def on_order_placed(order):
    telemetry.event("order.placed", {"order_id": order.id})
    telemetry.metric("storefront_requests_total", {"method": "POST", "route": "/orders", "status": "2xx", "order_id": order.id})
