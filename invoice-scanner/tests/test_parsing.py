import pytest

from invoice_scanner.parsing import parse_invoice_response


def test_parse_plain_json():
    payload = '{"supplier": {"value": "Acme"}, "lineItems": []}'
    data = parse_invoice_response(payload)
    assert data["supplier"]["value"] == "Acme"


def test_parse_fenced_json():
    payload = "```json\n{\"supplier\": {\"value\": \"Acme\"}}\n```"
    data = parse_invoice_response(payload)
    assert data["supplier"]["value"] == "Acme"


def test_parse_embedded_json():
    payload = "Here you go: {\"supplier\": {\"value\": \"Acme\"}} Thanks!"
    data = parse_invoice_response(payload)
    assert data["supplier"]["value"] == "Acme"


def test_parse_sets_empty_line_items():
    payload = "{\"supplier\": {\"value\": \"Acme\"}, \"lineItems\": null}"
    data = parse_invoice_response(payload)
    assert data["lineItems"] == []


def test_parse_rejects_missing_json():
    with pytest.raises(ValueError):
        parse_invoice_response("no json here")
