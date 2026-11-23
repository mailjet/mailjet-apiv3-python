"""OpenAPI manifest parity, release-drift detection, and sample helper loopback contract tests."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import mailjet_rest
from mailjet_rest import Client, Config
from mailjet_rest.client import _httpx2
from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP
from tests.integration.conftest import REPO_ROOT, load_openapi_manifest
from tests.integration.contracts._server import _extract_openapi_paths


if TYPE_CHECKING:
    import pytest

    from tests.integration.contracts._server import _ContractHTTPSServer


def test_route_map_deprecation_and_openapi_parity() -> None:
    """Verify ROUTE_MAP (89), DEPRECATION_ADVISORY (19), and OpenAPI manifests (99 + 15) stay synchronized."""
    manifest = load_openapi_manifest()
    assert len(ROUTE_MAP) == manifest["route_map_count"] == 89
    assert set(ROUTE_MAP) == set(manifest["route_contracts"])
    assert len(DEPRECATION_ADVISORY) == manifest["deprecation_advisory_count"] == 19
    assert set(DEPRECATION_ADVISORY).issubset(ROUTE_MAP)
    assert manifest["openapi_mailjet_count"] == 99
    assert len(manifest["openapi_mailjet_paths"]) == 99
    assert manifest["openapi_passport_count"] == 15
    assert len(manifest["openapi_passport_paths"]) == 15

    candidate_dirs = []
    if env_dir := os.environ.get("MAILJET_OPENAPI_DIR"):
        candidate_dirs.append(Path(env_dir))
    candidate_dirs.append(REPO_ROOT.parent / "mailjet_docs" / "release-docs-mailjet-rest")

    for spec_dir in candidate_dirs:
        mj_file = spec_dir / "openapi-mailjet.json"
        pp_file = spec_dir / "openapi-passport.json"
        if mj_file.is_file() and pp_file.is_file():
            live_mj = _extract_openapi_paths(json.loads(mj_file.read_text(encoding="utf-8")))
            live_pp = _extract_openapi_paths(json.loads(pp_file.read_text(encoding="utf-8")))
            assert set(live_mj) == set(manifest["openapi_mailjet_paths"]), "openapi-mailjet.json paths drifted!"
            assert set(live_pp) == set(manifest["openapi_passport_paths"]), "openapi-passport.json paths drifted!"
            for path_key, spec_meta in live_mj.items():
                assert spec_meta["methods"] == manifest["openapi_mailjet_paths"][path_key]["methods"]
            for path_key, spec_meta in live_pp.items():
                assert spec_meta["methods"] == manifest["openapi_passport_paths"][path_key]["methods"]
            break


def test_samples_public_helpers_against_loopback_contract(
    contract_tls_server: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Import public helpers from samples/ and execute them against the loopback TLS contract server."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(REPO_ROOT))

    account_settings_sample = importlib.import_module("samples.account_settings_sample")
    batch_sample = importlib.import_module("samples.batch_sample")
    campaign_sample = importlib.import_module("samples.campaign_sample")
    contacts_sample = importlib.import_module("samples.contacts_sample")
    content_api_sample = importlib.import_module("samples.content_api_sample")
    email_template_sample = importlib.import_module("samples.email_template_sample")
    getting_started_sample = importlib.import_module("samples.getting_started_sample")
    messages_sample = importlib.import_module("samples.messages_sample")
    parse_api_sample = importlib.import_module("samples.parse_api_sample")
    segments_sample = importlib.import_module("samples.segments_sample")
    sender_and_domain_samples = importlib.import_module("samples.sender_and_domain_samples")
    statistic_sample = importlib.import_module("samples.statistic_sample")
    webhooks_sample = importlib.import_module("samples.webhooks_sample")

    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    server: _ContractHTTPSServer = contract_tls_server["server"]

    with (
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v3", max_retries=0)) as c30,
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v3.1", max_retries=0)) as c31,
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v1", max_retries=0)) as c10,
    ):
        assert account_settings_sample.list_api_keys(client=c30).status_code == 200
        assert account_settings_sample.list_api_key_access(client=c30).status_code == 200
        assert account_settings_sample.get_my_profile(client=c30).status_code == 200
        assert account_settings_sample.get_user(client=c30).status_code == 200

        assert batch_sample.send_batch_payload(client=c30).status_code == 201
        assert batch_sample.list_batch_jobs(limit=1, client=c30).status_code == 200
        assert batch_sample.get_batch_job(job_id=123, client=c30).status_code == 200
        assert batch_sample.get_batch_job_csv_error(job_id=123, client=c30).status_code == 200

        assert campaign_sample.create_a_campaign_draft(client=c30).status_code == 201
        assert campaign_sample.by_adding_custom_content(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.schedule_the_campaign(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.send_the_campaign_right_away(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.api_call_requirements(client=c31).status_code == 200

        assert contacts_sample.create_a_contact(client=c30).status_code == 201
        assert contacts_sample.edit_contact_data(client=c30).status_code == 200
        assert contacts_sample.upload_the_csv(list_id=123, client=c30).status_code == 200
        assert contacts_sample.gdpr_delete_contact(contact_id=123, client=c30).status_code == 204
        assert contacts_sample.list_contactslist_signup_requests(client=c30).status_code == 200
        assert contacts_sample.verify_contactslist(list_id=123, client=c30).status_code == 201

        assert content_api_sample.generate_token(client=c10).status_code == 201
        assert content_api_sample.upload_image(client=c10).status_code == 201
        assert content_api_sample.list_v1_templates(client=c10).status_code == 200
        assert content_api_sample.publish_template_contents(template_id=123, client=c10).status_code == 200
        assert content_api_sample.unlock_template_contents(template_id=123, client=c10).status_code == 204
        assert content_api_sample.get_image_by_type(image_id=123, client=c10).status_code == 200

        assert email_template_sample.create_a_template(client=c30).status_code == 201
        assert email_template_sample.create_a_template_detailcontent(template_id=123, client=c30).status_code == 201
        assert email_template_sample.use_templates_with_send_api(client=c31).status_code == 200

        assert getting_started_sample.send_messages(client=c31).status_code == 200
        assert getting_started_sample.send_messages_with_builder(client=c31).status_code == 200
        assert getting_started_sample.retrieve_statistic(client=c30).status_code == 200

        assert messages_sample.list_messages(client=c30).status_code == 200
        assert messages_sample.get_message(message_id=123, client=c30).status_code == 200
        assert messages_sample.get_message_history(message_id=123, client=c30).status_code == 200
        assert messages_sample.get_message_information(message_id=123, client=c30).status_code == 200
        assert messages_sample.list_message_states(client=c30).status_code == 200

        assert parse_api_sample.basic_setup(client=c30).status_code in {200, 201}
        assert segments_sample.create_your_segment(client=c30).status_code == 201
        assert segments_sample.create_a_campaign_with_a_segmentation_filter(123, client=c30).status_code == 201

        assert sender_and_domain_samples.validate_an_entire_domain(dns_id=123, client=c30).status_code == 200
        assert sender_and_domain_samples.do_an_immediate_check_via_a_post(dns_id=123, client=c30).status_code == 201
        assert sender_and_domain_samples.host_a_text_file(sender_id=123, client=c30).status_code == 200
        assert sender_and_domain_samples.validation_by_doing_a_post(sender_id=123, client=c30).status_code == 201
        assert sender_and_domain_samples.list_metasenders(client=c30).status_code == 200

        assert statistic_sample.event_based_vs_message_based_stats_timing(client=c30).status_code == 200
        assert statistic_sample.view_the_spread_of_events_over_time(client=c30).status_code == 200
        assert statistic_sample.statistics_for_specific_recipient(client=c30).status_code == 200
        assert statistic_sample.stats_for_clicked_links(client=c30).status_code == 200
        assert statistic_sample.mailbox_provider_statistics(client=c30).status_code == 200
        assert statistic_sample.geographical_statistics(client=c30).status_code == 200
        assert statistic_sample.campaign_overview(client=c30).status_code == 200
        assert statistic_sample.list_recipient_statistics(client=c30).status_code == 200
        assert statistic_sample.top_links_clicked(client=c30).status_code == 200
        assert statistic_sample.user_agent_statistics(client=c30).status_code == 200

        assert webhooks_sample.verify_webhook_demo() is True
        assert webhooks_sample.list_webhooks(client=c30).status_code == 200
        assert webhooks_sample.setup_webhook(client=c30).status_code == 201
        assert webhooks_sample.get_webhook(123, client=c30).status_code == 200
        assert webhooks_sample.update_webhook(123, client=c30).status_code == 200
        assert webhooks_sample.delete_webhook(123, client=c30).status_code == 204

    if _httpx2 is not None:
        async_client_sample = importlib.import_module("samples.async_client_sample")
        monkeypatch.delenv("MJ_APIKEY_PUBLIC", raising=False)
        monkeypatch.delenv("MJ_APIKEY_PRIVATE", raising=False)
        asyncio.run(async_client_sample.main())

        orig_config = Config

        def _loopback_config(*args: Any, **kwargs: Any) -> Config:
            kwargs["api_url"] = url
            kwargs["verify"] = ca_path
            kwargs["max_retries"] = 0
            return orig_config(*args, **kwargs)

        monkeypatch.setenv("MJ_APIKEY_PUBLIC", "pub")
        monkeypatch.setenv("MJ_APIKEY_PRIVATE", "priv")
        monkeypatch.setattr(mailjet_rest, "Config", _loopback_config)

        server.clear_recorded()
        asyncio.run(async_client_sample.main())
        recorded = server.snapshot_recorded()
        assert any(r["method"] == "POST" and r["path"] == "/v3.1/send" for r in recorded)
        assert any(r["method"] == "PUT" and r["path"] == "/v3/REST/contact/123" for r in recorded)
