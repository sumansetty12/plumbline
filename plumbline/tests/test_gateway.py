import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from plumbline.gateway import (CONTRACT_ID_TAG, CONTRACTOR_TAG, Boto3Gateway, FakeGateway,
                               normalize_cloudtrail_event)

ASSUME = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}


def raw_event(**ct_over):
    ct = {"eventSource": "s3.amazonaws.com", "eventName": "GetObject", "sourceIPAddress": "203.0.113.5",
          "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/contractor-acme/plb-abc123"}}
    ct.update(ct_over)
    return {"EventId": "e-1", "EventTime": datetime(2026, 1, 5, 9, 30, tzinfo=timezone.utc),
            "Resources": [{"ResourceName": "acme-data"}], "CloudTrailEvent": json.dumps(ct)}


def test_normalize_assumed_role_event():
    e = normalize_cloudtrail_event(raw_event())
    assert e == {"id": "e-1", "time": "2026-01-05T09:30:00Z", "principal": "plb-abc123",
                 "principal_type": "AssumedRole", "role": "contractor-acme", "action": "s3:GetObject",
                 "resources": ["acme-data"], "error": None, "source_ip": "203.0.113.5"}


def test_normalize_keeps_error_code_and_maps_service_alias():
    e = normalize_cloudtrail_event(raw_event(eventSource="monitoring.amazonaws.com", eventName="GetMetricData",
                                             errorCode="AccessDenied"))
    assert e["action"] == "cloudwatch:GetMetricData" and e["error"] == "AccessDenied"


def test_normalize_iam_user_event():
    e = normalize_cloudtrail_event(raw_event(userIdentity={"type": "IAMUser", "userName": "vendor-bob",
                                                           "arn": "arn:aws:iam::1:user/vendor-bob"}))
    assert e["principal"] == "vendor-bob" and e["role"] is None


@mock_aws
def test_assume_role_sends_session_policy_and_duration():
    iam = boto3.client("iam", region_name="us-east-1")
    arn = iam.create_role(RoleName="contractor-acme", AssumeRolePolicyDocument=json.dumps(ASSUME))["Role"]["Arn"]
    gw = Boto3Gateway()
    pol = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    creds = gw.assume_role(arn, "plb-abc123", pol, 1800)
    assert creds["access_key_id"] and creds["session_token"] and creds["expiration"].endswith("Z")


@mock_aws
def test_revoke_sessions_installs_deny_older_than_policy():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="contractor-acme", AssumeRolePolicyDocument=json.dumps(ASSUME))
    gw = Boto3Gateway()
    gw.revoke_sessions("contractor-acme", datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc))
    doc = iam.get_role_policy(RoleName="contractor-acme", PolicyName="PlumblineRevokeOlderSessions")["PolicyDocument"]
    stmt = doc["Statement"][0] if isinstance(doc["Statement"], list) else doc["Statement"]
    assert stmt["Effect"] == "Deny" and stmt["Action"] == "*"
    assert stmt["Condition"]["DateLessThan"]["aws:TokenIssueTime"] == "2026-01-05T10:00:00Z"


@mock_aws
def test_list_contractor_principals_reads_tags_and_ignores_others():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="contractor-acme", AssumeRolePolicyDocument=json.dumps(ASSUME),
                    Tags=[{"Key": CONTRACTOR_TAG, "Value": "true"}, {"Key": CONTRACT_ID_TAG, "Value": "ctr_1"}])
    iam.create_role(RoleName="contractor-untagged-contract", AssumeRolePolicyDocument=json.dumps(ASSUME),
                    Tags=[{"Key": CONTRACTOR_TAG, "Value": "true"}])
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps(ASSUME))
    iam.create_user(UserName="vendor-bob", Tags=[{"Key": CONTRACTOR_TAG, "Value": "true"}])
    iam.create_user(UserName="employee")
    found = {p["name"]: p for p in Boto3Gateway().list_contractor_principals()}
    assert set(found) == {"contractor-acme", "contractor-untagged-contract", "vendor-bob"}
    assert found["contractor-acme"]["contract_id"] == "ctr_1" and found["contractor-acme"]["kind"] == "role"
    assert found["contractor-untagged-contract"]["contract_id"] is None
    assert found["vendor-bob"]["kind"] == "user"


def test_lookup_events_follows_pagination_and_filters_by_session():
    ct = boto3.client("cloudtrail", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
    start, end = datetime(2026, 1, 5, tzinfo=timezone.utc), datetime(2026, 1, 6, tzinfo=timezone.utc)
    page1 = {"Events": [{"EventId": "e-1", "EventTime": start, "CloudTrailEvent": raw_event()["CloudTrailEvent"],
                         "Resources": []}], "NextToken": "tok"}
    page2 = {"Events": [{"EventId": "e-2", "EventTime": start + timedelta(hours=1),
                         "CloudTrailEvent": raw_event(eventName="PutObject")["CloudTrailEvent"], "Resources": []}]}
    with Stubber(ct) as st:
        st.add_response("lookup_events", page1, {"StartTime": start, "EndTime": end,
                        "LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": "plb-abc123"}]})
        st.add_response("lookup_events", page2, {"StartTime": start, "EndTime": end, "NextToken": "tok",
                        "LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": "plb-abc123"}]})
        events = Boto3Gateway(cloudtrail=ct).lookup_events(start, end, "plb-abc123")
        st.assert_no_pending_responses()
    assert [e["action"] for e in events] == ["s3:GetObject", "s3:PutObject"]


def test_fake_gateway_enforces_sts_minimum():
    with pytest.raises(ValueError):
        FakeGateway().assume_role("arn:aws:iam::1:role/r", "s", "{}", 600)
