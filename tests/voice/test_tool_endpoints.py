def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_list_findings_endpoint(client):
    r = client.post("/tools/list_findings", json={})
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) == 10


def test_list_findings_filtered(client):
    r = client.post("/tools/list_findings", json={"severity": "critical", "status": "fail"})
    assert r.status_code == 200
    assert len(r.json()) == 4


def test_get_finding_endpoint(client):
    r = client.post("/tools/get_finding", json={"finding_id": "f-001"})
    assert r.status_code == 200
    assert r.json()["id"] == "f-001"


def test_get_finding_unknown_returns_200_with_error(client):
    r = client.post("/tools/get_finding", json={"finding_id": "nope"})
    assert r.status_code == 200
    assert r.json() == {"error": "finding_not_found", "finding_id": "nope"}


def test_get_compliance_score_endpoint(client):
    r = client.post("/tools/get_compliance_score", json={"framework": "soc2"})
    assert r.status_code == 200
    assert r.json()["framework"] == "soc2"


def test_get_multi_framework_score_endpoint(client):
    r = client.post("/tools/get_multi_framework_score", json={})
    assert r.status_code == 200
    assert "frameworks" in r.json()


def test_add_and_get_risk_endpoint(client):
    add = client.post(
        "/tools/add_risk_item",
        json={
            "account_id": "123456789012",
            "title": "x",
            "description": "y",
            "category": "iam",
            "likelihood": "low",
            "impact": "low",
            "treatment": "accept",
        },
    )
    assert add.status_code == 200
    rid = add.json()["record_id"]

    get = client.post("/tools/get_risk_item", json={"risk_id": rid})
    assert get.status_code == 200
    assert get.json()["risk_id"] == rid


def test_unknown_endpoint_returns_404(client):
    r = client.post("/tools/does_not_exist", json={})
    assert r.status_code == 404


def test_validates_severity_enum(client):
    r = client.post("/tools/list_findings", json={"severity": "extremely-critical"})
    assert r.status_code == 422
