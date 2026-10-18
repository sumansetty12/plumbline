"""Run with:  PLUMBLINE_DEMO=1 PLUMBLINE_KEYS='k1=alice@acme.example:contractor;k2=bob@corp.example:approver;k3=admin@corp.example:admin' \
              uvicorn plumbline.main:app

Real AWS mode: unset PLUMBLINE_DEMO and set AWS credentials. It then uses read access to IAM and
CloudTrail and sts:AssumeRole on each contract's role. Read the README's 'Before you point this at AWS' first.

Azure and/or GCP, in addition to AWS: set PLUMBLINE_AZURE_SUBSCRIPTION_ID and/or
PLUMBLINE_GCP_PROJECT_ID (with that cloud's own credentials available the way its SDK expects -
az login / a service-principal environment for Azure, GOOGLE_APPLICATION_CREDENTIALS or ADC for
GCP). Each extra provider needs its own optional dependency group installed
(pip install -e .[azure] / .[gcp]) and, for Azure, a Microsoft Graph client passed in by hand -
see AzureGateway's docstring in gateway_azure.py for why that one piece isn't wired up here."""
from __future__ import annotations

import os

from .api import create_app, parse_keys
from .app_factory import build
from .explain import AnthropicExplainer, TemplateExplainer


def make_app():
    keys = parse_keys(os.environ.get("PLUMBLINE_KEYS", ""))
    if not keys:
        raise SystemExit("Set PLUMBLINE_KEYS, e.g. 'k1=alice@acme.example:contractor;k2=bob@corp.example:approver'")
    demo = os.environ.get("PLUMBLINE_DEMO") == "1"
    gateways: dict = {}
    if demo:
        from .gateway import FakeGateway
        gateway = FakeGateway()
    else:
        from .gateway import Boto3Gateway
        gateway = Boto3Gateway(region=os.environ.get("AWS_REGION", "us-east-1"))
        if os.environ.get("PLUMBLINE_AZURE_SUBSCRIPTION_ID"):
            from .gateway_azure import AzureGateway
            gateways["azure"] = AzureGateway(subscription_id=os.environ["PLUMBLINE_AZURE_SUBSCRIPTION_ID"])
        if os.environ.get("PLUMBLINE_GCP_PROJECT_ID"):
            from .gateway_gcp import GCPGateway
            gateways["gcp"] = GCPGateway(project_id=os.environ["PLUMBLINE_GCP_PROJECT_ID"])
    explainer = AnthropicExplainer() if os.environ.get("ANTHROPIC_API_KEY") else TemplateExplainer()
    pl = build(gateway, db_path=os.environ.get("PLUMBLINE_DB", ":memory:" if demo else "plumbline.db"),
               explainer=explainer, gateways=gateways)
    if demo:
        from .demo import seed
        seed(pl)
    return create_app(pl, keys)


app = make_app() if os.environ.get("PLUMBLINE_KEYS") else None
