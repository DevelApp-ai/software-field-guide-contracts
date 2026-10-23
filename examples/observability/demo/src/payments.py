"""Payment handlers — instrumented within the declared contracts."""


def on_settled(payment):
    telemetry.event("payment.settled", {"payment_id": payment.id})
    telemetry.metric("payment_settlements_total", {"result": "ok", "provider": "provider-a"})


def on_refunded(payment):
    telemetry.event("payment.refunded", {"payment_id": payment.id})
    telemetry.metric("payment_settlements_total", {"result": "ok", "provider": "provider-a"})
