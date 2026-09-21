from services import sms_gateway


class FakeProvider:
    code = "fake"
    label = "Fake"

    def acquire(self, *, service, country, max_price):
        return {"activation_id": "remote-1", "phone": "+15550001111", "service": service,
                "country": country, "max_price": max_price}

    def status(self, activation_id):
        assert activation_id == "remote-1"
        return {"state": "ok", "code": "123456"}

    def complete(self, activation_id):
        assert activation_id == "remote-1"
        return "ACCESS_ACTIVATION"

    def cancel(self, activation_id):
        return "ACCESS_CANCEL"


def test_sms_activation_lifecycle_is_provider_neutral_and_durable(monkeypatch):
    sms_gateway.init_tables()
    monkeypatch.setitem(sms_gateway._PROVIDERS, "fake", FakeProvider())
    row = sms_gateway.acquire("fake", service="dr", country="187", max_price="0.16")
    assert row["state"] == "allocated"
    assert row["provider"] == "fake"
    refreshed = sms_gateway.refresh(row["id"])
    assert refreshed["state"] == "ok"
    assert refreshed["code"] == "123456"
    assert refreshed["code_received"] is True
    completed = sms_gateway.finish(row["id"], "complete")
    assert completed["state"] == "completed"
    assert any(item["id"] == row["id"] for item in sms_gateway.list_activations())
