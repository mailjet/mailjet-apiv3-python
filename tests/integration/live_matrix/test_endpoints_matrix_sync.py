"""Live 89-endpoint Mailjet & Passport sync matrix verifying active routes, deprecations, and release drift."""

from __future__ import annotations

import contextlib
import time
import uuid
import warnings
from collections.abc import Generator
from typing import Any

import pytest

from mailjet_rest import (
    Client,
    Config,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from tests.integration.conftest import get_live_auth, has_live_credentials
from tests.integration.live_matrix._matrix_spec import (
    _NONEXISTENT_ID,
    _NO_LIMIT_SINGLETON_ROUTES,
    _TIER_A_COLLECTION_ROUTES,
    _TIER_A_V1_COLLECTION_ROUTES,
    _TIER_B_COLLECTION_ROUTES,
    _TIER_B_PARAM_STATS_ROUTES,
    _TIER_B_SUBRESOURCE_PROBES,
    _TIER_C_RETIRED_ROUTES,
    COVERED_LIVE_ROUTES,
    LIVE_CREDENTIALS_REASON,
    SAFE_CAMPAIGNDRAFT_AND_DOMAIN_PROBES,
    STATCOUNTERS_FILTERS,
    assert_expected_deprecation_warning,
    assert_json_collection_response,
    assert_no_deprecation_warnings,
    assert_not_retired_or_disabled,
    build_send_v31_sandbox_payload,
    build_v1_image_files_payload,
    build_v1_template_content_payload,
    extract_first_id,
)


pytestmark = pytest.mark.skipif(not has_live_credentials(), reason=LIVE_CREDENTIALS_REASON)


@pytest.fixture
def live_v3() -> Generator[Client, None, None]:
    """Yield a shared v3 sync Mailjet client for live matrix assertions."""
    with Client(auth=get_live_auth(), config=Config(version="v3", max_retries=2)) as client:
        yield client


def test_live_matrix_covers_all_89_route_map_keys() -> None:
    """Guardrail ensuring every route in mailjet_rest.routes.ROUTE_MAP is exercised by this live matrix."""
    assert set(COVERED_LIVE_ROUTES) == set(ROUTE_MAP), (
        f"Uncovered: {sorted(set(ROUTE_MAP) - set(COVERED_LIVE_ROUTES))}, "
        f"Unknown: {sorted(set(COVERED_LIVE_ROUTES) - set(ROUTE_MAP))}"
    )


@pytest.mark.parametrize("route_name", _TIER_A_COLLECTION_ROUTES)
def test_live_tier_a_active_v3_collections(live_v3: Client, route_name: str) -> None:
    """Verify every active v3 GET collection route responds cleanly without deprecation or retirement."""
    ep = getattr(live_v3, route_name)
    t0 = time.monotonic()
    filters = None if route_name in _NO_LIMIT_SINGLETON_ROUTES else {"Limit": 1}
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("error", DeprecationWarning)
            resp = ep.get(filters=filters)
    except MailjetAuthError as exc:
        if exc.status_code in {401, 403} and route_name in {"apikey", "apikeyaccess"}:
            pytest.skip(f"API key lacks account-settings ACL for {route_name}: {exc.status_code}")
        raise
    except MailjetApiError as exc:
        assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
        raise

    assert_no_deprecation_warnings(caught)
    assert_json_collection_response(route_name, resp, time.monotonic() - t0)


@pytest.mark.parametrize("route_name", _TIER_A_V1_COLLECTION_ROUTES)
def test_live_tier_a_active_v1_collections(route_name: str) -> None:
    """Verify Passport Content API v1 GET collection routes work cleanly without DeprecationWarning."""
    with Client(auth=get_live_auth(), config=Config(version="v1", max_retries=2)) as client_v1:
        ep = getattr(client_v1, route_name)
        t0 = time.monotonic()
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("error", DeprecationWarning)
                resp = ep.get(filters={"Limit": 1})
        except MailjetAuthError as exc:
            if exc.status_code in {401, 403}:
                pytest.skip(f"Credentials lack v1 Content API permission for {route_name}: {exc.status_code}")
            raise
        except MailjetApiError as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            raise

        assert_no_deprecation_warnings(caught)
        assert_json_collection_response(route_name, resp, time.monotonic() - t0)


def test_live_active_parameterized_stats_and_messagehistory(live_v3: Client) -> None:
    """Verify statcounters, statistics_linkClick, statistics_recipientEsp, and messagehistory."""
    sc_resp = live_v3.statcounters.get(filters=STATCOUNTERS_FILTERS)
    assert_json_collection_response("statcounters", sc_resp, 0.0)

    cmp_resp = live_v3.campaign.get(filters={"Limit": 1})
    cmp_id = extract_first_id(cmp_resp)
    for stat_route in ("statistics_linkClick", "statistics_recipientEsp"):
        ep = getattr(live_v3, stat_route)
        try:
            res = ep.get(filters={"CampaignID": cmp_id})
            assert_json_collection_response(stat_route, res, 0.0)
        except (DoesNotExistError, ValidationError) as exc:
            assert_not_retired_or_disabled(stat_route, exc.status_code, exc.response_body)
            assert exc.status_code in {400, 404}

    msg_resp = live_v3.message.get(filters={"Limit": 1})
    msg_id = extract_first_id(msg_resp)
    try:
        mh_resp = live_v3.messagehistory.get(id=msg_id)
        assert_json_collection_response("messagehistory", mh_resp, 0.0)
    except (DoesNotExistError, ValidationError) as exc:
        assert_not_retired_or_disabled("messagehistory", exc.status_code, exc.response_body)
        assert exc.status_code in {400, 404}


@pytest.mark.parametrize("route_name", _TIER_B_COLLECTION_ROUTES)
def test_live_tier_b_deprecated_collections_detect_retirement(live_v3: Client, route_name: str) -> None:
    """Verify deprecated v3 collections emit DeprecationWarning and detect any server-side 410/Unknown retirement."""
    ep = getattr(live_v3, route_name)
    filters = None if route_name in _NO_LIMIT_SINGLETON_ROUTES else {"Limit": 1}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        try:
            resp = ep.get(filters=filters)
            assert_json_collection_response(route_name, resp, 0.0)
        except (DoesNotExistError, ValidationError) as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            assert exc.status_code in {400, 404}
        except MailjetApiError as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            raise

    assert_expected_deprecation_warning(caught, route_name)


@pytest.mark.parametrize("route_name", _TIER_B_PARAM_STATS_ROUTES)
def test_live_tier_b_parameterized_deprecated_statistics(live_v3: Client, route_name: str) -> None:
    """Verify campaigngraphstatistics (IDS) and graphstatistics (Scale) emit warnings without server retirement."""
    cmp_resp = live_v3.campaign.get(filters={"Limit": 1})
    cmp_id = extract_first_id(cmp_resp, default=1)
    filters = {"IDS": str(cmp_id), "Limit": 1} if route_name == "campaigngraphstatistics" else {"Scale": "Day"}

    ep = getattr(live_v3, route_name)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        try:
            resp = ep.get(filters=filters)
            assert_json_collection_response(route_name, resp, 0.0)
        except (DoesNotExistError, ValidationError) as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            assert exc.status_code in {400, 404}
        except MailjetApiError as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            raise

    assert_expected_deprecation_warning(caught)


@pytest.mark.parametrize(("route_name", "method_name"), _TIER_B_SUBRESOURCE_PROBES)
def test_live_tier_b_newsletter_subresource_probes(live_v3: Client, route_name: str, method_name: str) -> None:
    """Safely probe deprecated newsletter_* sub-resources on a non-existent ID without mutating or sending mail."""
    ep = getattr(live_v3, route_name)
    fn = getattr(ep, method_name)
    call_kwargs: dict[str, Any] = {"id": _NONEXISTENT_ID}
    if method_name == "create":
        call_kwargs["data"] = {}

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        try:
            resp = fn(**call_kwargs)
            assert resp.status_code in {200, 201}
        except (DoesNotExistError, ValidationError) as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            assert exc.status_code in {400, 404}

    assert_expected_deprecation_warning(caught)


@pytest.mark.parametrize("route_name", _TIER_C_RETIRED_ROUTES)
def test_live_tier_c_known_retired_endpoints(live_v3: Client, route_name: str) -> None:
    """Confirm known server-retired aliases (webhook, messagesentstatistics) trigger advisories and expected 400/410."""
    ep = getattr(live_v3, route_name)
    filters = None if route_name in _NO_LIMIT_SINGLETON_ROUTES else {"Limit": 1}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        try:
            resp = ep.get(filters=filters)
            assert resp.status_code == 200
        except MailjetApiError as exc:
            assert exc.status_code in {400, 404, 410}
            if route_name == "webhook":
                assert "webhook" in exc.response_body.lower()

    assert_expected_deprecation_warning(caught)


def test_live_send_batch_and_csverror_routes(live_v3: Client) -> None:
    """Exercise send_v31 (SandboxMode), send (v3), batch, and batchjob_csverror without delivering real email."""
    with Client(auth=get_live_auth(), config=Config(version="v3.1", max_retries=2)) as client_v31:
        ok_resp = client_v31.send_v31.create(data=build_send_v31_sandbox_payload())
        assert ok_resp.status_code == 200
        assert "Messages" in ok_resp.json()

        with pytest.raises(ValidationError) as exc_v31:
            client_v31.send_v31.create(data={"InvalidKey": True})
        assert exc_v31.value.status_code == 400

    with pytest.raises(ValidationError) as exc_send_v3:
        live_v3.send.create(data={})
    assert_not_retired_or_disabled("send", exc_send_v3.value.status_code, exc_send_v3.value.response_body)
    assert exc_send_v3.value.status_code == 400

    try:
        batch_resp = live_v3.batch.create(data={})
        assert_not_retired_or_disabled("batch", batch_resp.status_code, batch_resp.text)
    except MailjetApiError as exc_batch:
        assert_not_retired_or_disabled("batch", exc_batch.status_code, exc_batch.response_body)
        assert exc_batch.status_code in {400, 401, 403, 404}

    try:
        csv_err_resp = live_v3.batchjob_csverror.get(id=_NONEXISTENT_ID)
        assert csv_err_resp.status_code in {200, 204}
    except (DoesNotExistError, ValidationError) as exc_csv:
        assert_not_retired_or_disabled("batchjob_csverror", exc_csv.status_code, exc_csv.response_body)
        assert exc_csv.status_code in {400, 404}


def test_live_contacts_lists_segmentation_csv_and_v4_gdpr_lifecycle(live_v3: Client) -> None:
    """Exercise contact, contactdata, contactmetadata, contactslist*, listrecipient, contactfilter, csvimport, and v4 contacts."""
    suffix = uuid.uuid4().hex[:8]
    test_email = f"ci-matrix-{suffix}@example.com"
    dst_list_id: int | None = None
    src_list_id: int | None = None
    contact_id: int | None = None
    filter_id: int | None = None
    metadata_id: int | None = None

    try:
        dst_list_resp = live_v3.contactslist.create(data={"Name": f"CI_Matrix_Dst_{suffix}"})
        assert dst_list_resp.status_code == 201
        dst_list_id = dst_list_resp.json()["Data"][0]["ID"]

        src_list_resp = live_v3.contactslist.create(data={"Name": f"CI_Matrix_Src_{suffix}"})
        assert src_list_resp.status_code == 201
        src_list_id = src_list_resp.json()["Data"][0]["ID"]

        contact_resp = live_v3.contact.create(data={"Email": test_email, "IsExcludedFromCampaigns": True})
        assert contact_resp.status_code == 201
        contact_id = contact_resp.json()["Data"][0]["ID"]

        # 1. contactdata GET + PUT
        cd_get = live_v3.contactdata.get(id=contact_id)
        assert cd_get.status_code == 200
        meta_prop_name: str | None = None
        try:
            meta_prop_name = f"ci_prop_{suffix}"
            cm_resp = live_v3.contactmetadata.create(
                data={"Datatype": "str", "Name": meta_prop_name, "NameSpace": "static"}
            )
            assert cm_resp.status_code == 201
            metadata_id = cm_resp.json()["Data"][0]["ID"]
        except ValidationError as exc_meta:
            assert_not_retired_or_disabled("contactmetadata", exc_meta.status_code, exc_meta.response_body)
            existing_meta = live_v3.contactmetadata.get(filters={"Limit": 1}).json().get("Data", [])
            if existing_meta and existing_meta[0].get("Datatype") == "str":
                meta_prop_name = existing_meta[0]["Name"]
            else:
                meta_prop_name = None

        if meta_prop_name is not None:
            cd_put = live_v3.contactdata.update(
                id=contact_id,
                data={"Data": [{"Name": meta_prop_name, "Value": "matrix_ok"}]},
            )
            assert cd_put.status_code == 200

        # 2. contactfilter CRUD
        cf_create = live_v3.contactfilter.create(
            data={"Description": "Matrix temp filter", "Expression": "(age<35)", "Name": f"CI_Filter_{suffix}"}
        )
        assert cf_create.status_code == 201
        filter_id = cf_create.json()["Data"][0]["ID"]
        assert live_v3.contactfilter.get(id=filter_id).status_code == 200
        assert live_v3.contactfilter.update(id=filter_id, data={"Description": "Updated"}).status_code == 200

        # 3. listrecipient CRUD
        lr_create = live_v3.listrecipient.create(
            data={"ContactID": contact_id, "ListID": dst_list_id, "IsUnsubscribed": False}
        )
        assert lr_create.status_code == 201
        lr_id = lr_create.json()["Data"][0]["ID"]
        try:
            assert live_v3.listrecipient.get(id=lr_id).status_code == 200
            assert live_v3.listrecipient.update(id=lr_id, data={"IsUnsubscribed": True}).status_code == 200
        finally:
            with contextlib.suppress(DoesNotExistError):
                live_v3.listrecipient.delete(id=lr_id)

        # 4. contact_managecontactslists, contact_getcontactslists, contactslist_managecontact
        mcl_resp = live_v3.contact_managecontactslists.create(
            id=contact_id,
            data={"ContactsLists": [{"ListID": src_list_id, "Action": "addnoforce"}]},
        )
        assert mcl_resp.status_code in {200, 201}
        assert live_v3.contact_getcontactslists.get(id=contact_id).status_code == 200

        mc_resp = live_v3.contactslist_managecontact.create(
            id=dst_list_id,
            data={"Email": test_email, "Action": "addnoforce"},
        )
        assert mc_resp.status_code in {200, 201}

        # 5. contactslist_managemanycontacts + contact_managemanycontacts POST & GET/{job_ID}
        l_mmc = live_v3.contactslist_managemanycontacts.create(
            id=dst_list_id,
            data={"Action": "addnoforce", "Contacts": [{"Email": test_email}]},
        )
        assert l_mmc.status_code in {200, 201}
        if l_mmc_data := l_mmc.json().get("Data"):
            if l_job_id := l_mmc_data[0].get("JobID"):
                assert (
                    live_v3.contactslist_managemanycontacts.get(id=dst_list_id, action_id=l_job_id).status_code == 200
                )

        c_mmc = live_v3.contact_managemanycontacts.create(
            data={
                "Contacts": [{"Email": test_email, "IsExcludedFromCampaigns": True}],
                "ContactsLists": [{"ListID": src_list_id, "Action": "addnoforce"}],
            }
        )
        assert c_mmc.status_code in {200, 201}
        if c_mmc_data := c_mmc.json().get("Data"):
            if c_job_id := c_mmc_data[0].get("JobID"):
                assert live_v3.contact_managemanycontacts.get(id=c_job_id).status_code == 200

        # 6. contactslist_importlist & contactslist_verify
        imp_list = live_v3.contactslist_importlist.create(
            id=dst_list_id,
            data={"Action": "addnoforce", "ListID": src_list_id},
        )
        assert imp_list.status_code in {200, 201}
        if imp_data := imp_list.json().get("Data"):
            if imp_job_id := imp_data[0].get("JobID"):
                assert live_v3.contactslist_importlist.get(id=dst_list_id, action_id=imp_job_id).status_code == 200

        try:
            ver_resp = live_v3.contactslist_verify.create(id=dst_list_id, data={"Method": "fulllist"})
            assert_not_retired_or_disabled("contactslist_verify", ver_resp.status_code, ver_resp.text)
            assert ver_resp.status_code in {200, 201}
        except MailjetApiError as exc_ver:
            assert_not_retired_or_disabled("contactslist_verify", exc_ver.status_code, exc_ver.response_body)
            assert exc_ver.status_code in {400, 401, 402, 403, 404}

        # 7. contactslist_csvdata upload + csvimport create/monitor
        csv_payload = f"email,IsExcludedFromCampaigns\n{test_email},true\n"
        csv_up = live_v3.contactslist_csvdata.create(id=dst_list_id, data=csv_payload)
        assert csv_up.status_code == 200
        data_id = csv_up.json().get("ID") or csv_up.json()["Data"][0]["ID"]
        csv_imp = live_v3.csvimport.create(
            data={"Method": "addnoforce", "ContactsListID": dst_list_id, "DataID": data_id}
        )
        assert csv_imp.status_code == 201
        import_job_id = csv_imp.json()["Data"][0]["ID"]
        assert live_v3.csvimport.get(id=import_job_id).status_code == 200
    finally:
        if filter_id is not None:
            with contextlib.suppress(MailjetApiError):
                live_v3.contactfilter.delete(id=filter_id)
        if metadata_id is not None:
            with contextlib.suppress(MailjetApiError):
                live_v3.contactmetadata.delete(id=metadata_id)
        for lid in (src_list_id, dst_list_id):
            if lid is not None:
                with contextlib.suppress(MailjetApiError):
                    live_v3.contactslist.delete(id=lid)

        # Clean contact via v3 (if permitted) and v4 GDPR endpoint
        if contact_id is not None:
            with contextlib.suppress(MailjetApiError):
                live_v3.contact.delete(id=contact_id)
            try:
                gdpr_resp = live_v3.contacts.delete(id=contact_id)
                assert gdpr_resp.status_code in {200, 204}
            except MailjetApiError as exc_gdpr:
                assert_not_retired_or_disabled("contacts", exc_gdpr.status_code, exc_gdpr.response_body)
                assert exc_gdpr.status_code in {400, 401, 403, 404}


def test_live_parseroute_campaigndraft_sender_dns_probes(live_v3: Client) -> None:
    """Safely verify parseroute, campaigndraft* actions, sender_validate, and dns_check without global mutations."""
    pr_list = live_v3.parseroute.get()
    assert pr_list.status_code == 200
    existing_pr = pr_list.json().get("Data", [])
    if not existing_pr:
        try:
            pr_create = live_v3.parseroute.create(data={"Url": f"https://example.com/parse_{uuid.uuid4().hex[:8]}"})
        except ValidationError as exc_pr:
            assert_not_retired_or_disabled("parseroute", exc_pr.status_code, exc_pr.response_body)
            pr_retry = live_v3.parseroute.get()
            assert pr_retry.status_code == 200
            retry_pr = pr_retry.json().get("Data", [])
            if retry_pr:
                with contextlib.suppress(DoesNotExistError):
                    assert live_v3.parseroute.get(id=retry_pr[0]["ID"]).status_code == 200
            elif "mj18" not in exc_pr.response_body.lower():
                raise
        else:
            assert pr_create.status_code == 201
            pr_id = pr_create.json()["Data"][0]["ID"]
            try:
                assert live_v3.parseroute.get(id=pr_id).status_code == 200
                assert (
                    live_v3.parseroute.update(
                        id=pr_id, data={"Url": f"https://example.com/parse_upd_{uuid.uuid4().hex[:8]}"}
                    ).status_code
                    == 200
                )
            finally:
                assert live_v3.parseroute.delete(id=pr_id).status_code in {200, 204}
    else:
        with contextlib.suppress(DoesNotExistError):
            assert live_v3.parseroute.get(id=existing_pr[0]["ID"]).status_code == 200

    drafts = live_v3.campaigndraft.get(filters={"Limit": 1}).json().get("Data", [])
    if drafts:
        draft_id = drafts[0]["ID"]
        assert live_v3.campaigndraft.get(id=draft_id).status_code == 200
        assert live_v3.campaigndraft_status.get(id=draft_id).status_code == 200
    else:
        with pytest.raises((DoesNotExistError, ValidationError)) as exc_status:
            live_v3.campaigndraft_status.get(id=_NONEXISTENT_ID)
        assert_not_retired_or_disabled(
            "campaigndraft_status", exc_status.value.status_code, exc_status.value.response_body
        )

    for route_name, method_name, kwargs in SAFE_CAMPAIGNDRAFT_AND_DOMAIN_PROBES:
        ep = getattr(live_v3, route_name)
        try:
            res = getattr(ep, method_name)(**kwargs)
            assert res.status_code in {200, 201}
        except MailjetApiError as exc:
            assert_not_retired_or_disabled(route_name, exc.status_code, exc.response_body)
            assert exc.status_code in {400, 401, 403, 404}


def test_live_templates_v3_and_content_api_v1_full_lifecycle(live_v3: Client) -> None:
    """Verify template_update, templates_contents (deprecated alias), and all v1 Passport endpoints."""
    suffix = uuid.uuid4().hex[:8]

    # 1. v3 template_update (deprecated alias) + template_detailcontent
    tpl_resp = live_v3.template.create(
        data={"Name": f"CI_Upd_{suffix}", "Author": "Matrix", "EditMode": 1, "Purposes": ["transactional"]}
    )
    assert tpl_resp.status_code == 201
    tpl_id = tpl_resp.json()["Data"][0]["ID"]
    try:
        with warnings.catch_warnings(record=True) as w_upd:
            warnings.simplefilter("always", DeprecationWarning)
            upd_resp = live_v3.template_update.update(
                id=tpl_id, data={"Name": f"CI_Upd_{suffix}", "Description": "Updated via alias"}
            )
        assert upd_resp.status_code == 200
        assert_expected_deprecation_warning(w_upd)

        dc_resp = live_v3.template_detailcontent.create(
            id=tpl_id,
            data={"Html-part": "<p>Matrix v3</p>", "Text-part": "Matrix v3", "Headers": {"Subject": "Matrix"}},
        )
        assert dc_resp.status_code in {200, 201}
    finally:
        live_v3.template.delete(id=tpl_id)

    # 2. Content API v1 canonical routes + deprecated templates_contents alias
    with Client(auth=get_live_auth(), config=Config(version="v1", max_retries=2)) as client_v1:
        try:
            v1_create = client_v1.v1_templates.create(
                data={"Name": f"ci-v1-matrix-{suffix}", "EditMode": 2, "Purposes": ["transactional"]}
            )
            assert v1_create.status_code == 201
            v1_tpl_id = v1_create.json()["Data"][0]["ID"]
            try:
                assert (
                    client_v1.template_contents.create(
                        id=v1_tpl_id, data=build_v1_template_content_payload()
                    ).status_code
                    == 201
                )
                with warnings.catch_warnings(record=True) as w_tc:
                    warnings.simplefilter("always", DeprecationWarning)
                    assert client_v1.templates_contents.get(id=v1_tpl_id).status_code == 200
                assert_expected_deprecation_warning(w_tc)

                assert client_v1.template_contents_publish.create(id=v1_tpl_id).status_code == 200
                assert client_v1.template_content_by_type.get(id=v1_tpl_id, action_id="P").status_code == 200
                assert client_v1.template_contents_lock.create(id=v1_tpl_id, data={}).status_code == 204
                assert client_v1.template_contents_unlock.create(id=v1_tpl_id, data={}).status_code == 204
            finally:
                with contextlib.suppress(MailjetApiError):
                    client_v1.v1_templates.delete(id=v1_tpl_id)
        except MailjetApiError as exc_v1_tpl:
            assert_not_retired_or_disabled("v1_templates", exc_v1_tpl.status_code, exc_v1_tpl.response_body)
            if exc_v1_tpl.status_code not in {401, 403}:
                raise

        # 3. v1 labels CRUD (ephemeral + cleanup)
        try:
            lbl_create = client_v1.labels.create(
                data={"Name": f"ci-lbl-{suffix}", "Color": "#225588", "UsedFor": "resource"}
            )
            assert lbl_create.status_code == 201
            lbl_id = lbl_create.json()["Data"][0]["ID"]
            try:
                assert client_v1.labels.get(id=lbl_id).status_code == 200
                assert (
                    client_v1.labels.update(
                        id=lbl_id, data={"Name": f"ci-lbl-upd-{suffix}", "Color": "#113355"}
                    ).status_code
                    == 200
                )
            finally:
                with contextlib.suppress(MailjetApiError):
                    client_v1.labels.delete(id=lbl_id)
        except MailjetApiError as exc_lbl:
            assert_not_retired_or_disabled("labels", exc_lbl.status_code, exc_lbl.response_body)
            assert exc_lbl.status_code in {400, 401, 403}

        # 4. v1 tokens non-mutating check (avoid creating undeletable tokens)
        assert client_v1.tokens.get(filters={"Limit": 1}).status_code == 200
        with pytest.raises((DoesNotExistError, ValidationError, MailjetAuthError)) as exc_tok:
            client_v1.tokens.update(id=_NONEXISTENT_ID, data={})
        assert_not_retired_or_disabled("tokens", exc_tok.value.status_code, exc_tok.value.response_body)

        # 5. v1 images + data_images + data_images_by_type
        imgs = client_v1.images.get(filters={"Limit": 1})
        assert imgs.status_code == 200
        img_name = f"ci_matrix_{suffix}.png"
        try:
            up_resp = client_v1.data_images.create(
                headers={"Content-Type": None}, files=build_v1_image_files_payload(img_name)
            )
            assert up_resp.status_code in {200, 201}
            image_id = up_resp.json()["Data"][0]["ID"]
            try:
                assert client_v1.images.get(id=image_id).status_code == 200
                put_img = client_v1.data_images_by_type.update(
                    id=image_id,
                    action_id="content",
                    headers={"Content-Type": None},
                    files=build_v1_image_files_payload(img_name, include_metadata=False),
                )
                assert put_img.status_code in {200, 201}
            finally:
                with contextlib.suppress(MailjetApiError):
                    client_v1.images.delete(id=image_id)
        except (ValidationError, MailjetAuthError) as exc_img:
            assert_not_retired_or_disabled("data_images", exc_img.status_code, exc_img.response_body)
            with pytest.raises((DoesNotExistError, ValidationError, MailjetAuthError)) as exc_img_type:
                client_v1.data_images_by_type.update(id=_NONEXISTENT_ID, action_id="content", data={})
            assert_not_retired_or_disabled(
                "data_images_by_type", exc_img_type.value.status_code, exc_img_type.value.response_body
            )
