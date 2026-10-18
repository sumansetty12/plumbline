import pytest

from plumbline import identifiers as ids

AWS_REF = "arn:aws:iam::123456789012:role/contractor-acme"
AZURE_REF = ("11111111-1111-1111-1111-111111111111@/subscriptions/"
            "22222222-2222-2222-2222-222222222222/resourceGroups/acme-rg"
            "#33333333-3333-3333-3333-333333333333")
GCP_REF = "contractor-acme@my-project.iam.gserviceaccount.com"


@pytest.mark.parametrize("provider,ref", [("aws", AWS_REF), ("azure", AZURE_REF), ("gcp", GCP_REF)])
def test_valid_refs_pass(provider, ref):
    ids.validate(provider, ref)  # must not raise


@pytest.mark.parametrize("provider,ref", [
    ("aws", "not-an-arn"),
    ("aws", GCP_REF),
    ("azure", "just-a-guid"),
    ("azure", AWS_REF),
    ("gcp", "not-an-email"),
    ("gcp", AWS_REF),
])
def test_bad_refs_are_rejected(provider, ref):
    with pytest.raises(ids.BadPrincipalRef):
        ids.validate(provider, ref)


def test_unknown_provider_is_rejected():
    with pytest.raises(ids.BadPrincipalRef):
        ids.validate("digitalocean", AWS_REF)
    with pytest.raises(ids.BadPrincipalRef):
        ids.duration_bounds("digitalocean")


def test_principal_handle_aws_strips_to_short_role_name():
    assert ids.principal_handle("aws", AWS_REF) == "contractor-acme"


def test_principal_handle_azure_and_gcp_keep_the_full_reference():
    assert ids.principal_handle("azure", AZURE_REF) == AZURE_REF
    assert ids.principal_handle("gcp", GCP_REF) == GCP_REF


def test_duration_bounds_reflect_each_providers_real_limit():
    assert ids.duration_bounds("aws") == (900, 43200)
    assert ids.duration_bounds("azure") == (300, 86400)
    assert ids.duration_bounds("gcp") == (600, 3600)  # GCP tokens cap at 1 hour
