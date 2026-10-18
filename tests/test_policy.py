import pytest

from plumbline import policy as p


def stmts(actions, resources="*"):
    return p.normalize({"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]})


def test_normalize_accepts_single_statement_and_strings():
    out = p.normalize({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})
    assert out == [{"actions": ["s3:GetObject"], "resources": ["*"]}]


@pytest.mark.parametrize("bad", [
    {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*", "Condition": {}}]},
    {"Statement": []},
    {"Nope": 1},
    {"Statement": [{"Effect": "Allow", "Action": "notanaction", "Resource": "*"}]},
])
def test_normalize_rejects_unsupported(bad):
    with pytest.raises(p.PolicyError):
        p.normalize(bad)


def test_normalize_rejects_invalid_json():
    with pytest.raises(p.PolicyError):
        p.normalize("{not json")


def test_ceiling_allows_narrower_request():
    ceiling = stmts(["s3:Get*"], "arn:aws:s3:::acme-*")
    ok, v = p.is_within_ceiling(stmts(["s3:GetObject"], "arn:aws:s3:::acme-data"), ceiling)
    assert ok and not v


def test_ceiling_rejects_wildcard_that_is_broader():
    ceiling = stmts(["s3:Get*"], "*")
    ok, v = p.is_within_ceiling(stmts(["s3:*"]), ceiling)
    assert not ok and "s3:*" in v[0]


def test_ceiling_rejects_other_resource():
    ceiling = stmts(["s3:Get*"], "arn:aws:s3:::acme-*")
    ok, _ = p.is_within_ceiling(stmts(["s3:GetObject"], "arn:aws:s3:::other-bucket"), ceiling)
    assert not ok


def test_ceiling_action_match_is_case_insensitive_but_resource_is_not():
    ceiling = stmts(["S3:GET*"], "arn:aws:s3:::Acme")
    assert p.is_within_ceiling(stmts(["s3:getobject"], "arn:aws:s3:::Acme"), ceiling)[0]
    assert not p.is_within_ceiling(stmts(["s3:getobject"], "arn:aws:s3:::acme"), ceiling)[0]


@pytest.mark.parametrize("action,expected", [
    ("s3:GetObject", "read"), ("ec2:DescribeInstances", "read"), ("s3:PutObject", "write"),
    ("s3:DeleteBucket", "destructive"), ("ec2:TerminateInstances", "destructive"),
    ("iam:PassRole", "privilege"), ("iam:CreateAccessKey", "privilege"), ("iam:ListUsers", "read"),
    ("secretsmanager:GetSecretValue", "secret-read"), ("kms:Decrypt", "secret-read"),
    ("s3:*", "admin"), ("*", "admin"), ("s3:Get*", "read"), ("iam:Create*", "privilege"),
    ("secretsmanager:Get*", "secret-read"),
])
def test_classify_action(action, expected):
    assert p.classify_action(action) == expected


def test_blast_radius_levels():
    low = p.blast_radius(stmts(["s3:GetObject"], "arn:aws:s3:::a/*"))
    assert low["risk"] == "low"
    assert p.blast_radius(stmts(["s3:PutObject"], "arn:aws:s3:::a/*"))["risk"] == "medium"
    assert p.blast_radius(stmts(["s3:DeleteObject"], "arn:aws:s3:::a/*"))["risk"] == "high"
    assert p.blast_radius(stmts(["s3:PutObject"], "*"))["risk"] == "high"
    assert p.blast_radius(stmts(["iam:PassRole"], "arn:aws:iam::1:role/x"))["risk"] == "critical"
    assert p.blast_radius(stmts(["ec2:*"]))["risk"] == "critical"


def test_blast_radius_explains_in_plain_language():
    b = p.blast_radius(stmts(["iam:PassRole", "s3:GetObject"]))
    text = " ".join(b["reasons"])
    assert "grant themselves more access" in text
    assert b["services"] == ["iam", "s3"]


def test_session_policy_size_limit():
    big = stmts([f"s3:Action{i}" for i in range(400)])
    with pytest.raises(p.PolicyError):
        p.session_policy_json(big)


def test_right_size_keeps_only_used_actions_with_observed_resources():
    req = stmts(["s3:GetObject", "s3:ListBucket", "s3:GetObjectAcl"], ["arn:aws:s3:::a", "arn:aws:s3:::a/*"])
    used = [{"action": "s3:GetObject", "resources": ["arn:aws:s3:::a/report.csv"]},
            {"action": "s3:GetObject", "resources": ["arn:aws:s3:::a/other.csv"]}]
    r = p.right_size(req, used)
    st = r["suggested_policy"]["Statement"]
    assert len(st) == 1 and st[0]["Action"] == ["s3:GetObject"]
    assert st[0]["Resource"] == ["arn:aws:s3:::a/other.csv", "arn:aws:s3:::a/report.csv"]
    assert r["unused_action_patterns"] == ["s3:GetObjectAcl", "s3:ListBucket"]
    assert r["actions_actually_used"] == 1


def test_right_size_never_broader_than_request():
    req = stmts(["s3:Get*"], ["arn:aws:s3:::a/*"])
    r = p.right_size(req, [{"action": "s3:GetObject", "resources": []}])
    assert r["suggested_policy"]["Statement"][0]["Resource"] == ["arn:aws:s3:::a/*"]


def test_right_size_with_no_usage_suggests_nothing():
    r = p.right_size(stmts(["s3:GetObject"]), [])
    assert r["suggested_policy"] is None


# ---------- multi-cloud: action syntax, classification, per-provider blast radius ----------

def azure_stmts(actions, resources="/subscriptions/1/resourceGroups/rg"):
    return p.normalize({"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}, "azure")


def gcp_stmts(actions, resources="projects/my-project/buckets/acme-data"):
    return p.normalize({"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]}, "gcp")


def test_normalize_accepts_well_formed_azure_and_gcp_actions():
    assert azure_stmts(["Microsoft.Storage/storageAccounts/blobServices/containers/read"])
    assert gcp_stmts(["storage.objects.get", "storage.objects.list"])


def test_normalize_rejects_aws_style_action_for_other_providers():
    with pytest.raises(p.PolicyError):
        azure_stmts(["s3:GetObject"])
    with pytest.raises(p.PolicyError):
        gcp_stmts(["s3:GetObject"])


def test_normalize_rejects_malformed_provider_actions():
    with pytest.raises(p.PolicyError):
        azure_stmts(["not an action"])
    with pytest.raises(p.PolicyError):
        gcp_stmts(["NotLowerCaseStart"])


@pytest.mark.parametrize("action,expected", [
    ("Microsoft.Storage/storageAccounts/blobServices/containers/read", "read"),
    ("Microsoft.Storage/storageAccounts/write", "write"),
    ("Microsoft.Storage/storageAccounts/delete", "destructive"),
    ("Microsoft.Authorization/roleAssignments/write", "privilege"),
    ("Microsoft.Authorization/roleAssignments/read", "read"),
    ("*", "admin"),
])
def test_classify_action_azure(action, expected):
    assert p.classify_action(action, "azure") == expected


@pytest.mark.parametrize("action,expected", [
    ("storage.objects.get", "read"),
    ("storage.objects.list", "read"),
    ("storage.objects.create", "write"),
    ("storage.objects.delete", "destructive"),
    ("storage.buckets.setIamPolicy", "privilege"),
    ("iam.serviceAccounts.actAs", "privilege"),
    ("secretmanager.versions.access", "secret-read"),
    ("*", "admin"),
])
def test_classify_action_gcp(action, expected):
    assert p.classify_action(action, "gcp") == expected


def test_blast_radius_azure_privilege_and_destructive():
    low = p.blast_radius(azure_stmts(["Microsoft.Storage/storageAccounts/blobServices/containers/read"]), "azure")
    assert low["risk"] == "low"
    crit = p.blast_radius(azure_stmts(["Microsoft.Authorization/roleAssignments/write"]), "azure")
    assert crit["risk"] == "critical"


def test_blast_radius_gcp_privilege_and_destructive():
    low = p.blast_radius(gcp_stmts(["storage.objects.get"]), "gcp")
    assert low["risk"] == "low"
    crit = p.blast_radius(gcp_stmts(["storage.buckets.setIamPolicy"]), "gcp")
    assert crit["risk"] == "critical"
    high = p.blast_radius(gcp_stmts(["storage.objects.delete"]), "gcp")
    assert high["risk"] == "high"


def test_session_policy_json_size_limit_is_aws_only():
    huge = stmts(["s3:GetObject"], [f"arn:aws:s3:::bucket-{i}" for i in range(400)])
    with pytest.raises(p.PolicyError):
        p.session_policy_json(huge, "aws")
    azure_huge = azure_stmts(["Microsoft.Storage/storageAccounts/blobServices/containers/read"] * 1,
                             resources=[f"/subscriptions/1/resourceGroups/rg-{i}" for i in range(400)])
    text = p.session_policy_json(azure_huge, "azure")  # no AWS-sized ceiling applies
    assert len(text) > 2048
