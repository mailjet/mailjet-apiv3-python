"""Stateful property tests for MessageBuilder and SendPayloadBuilder.
Hypothesis exercises arbitrary rule sequences and enforces structural and isolation invariants.
"""

import warnings

import pytest
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder
from mailjet_rest.utils.guardrails import SecurityGuard


class MessageBuilderMachine(RuleBasedStateMachine):
    @initialize()
    def init_builder(self) -> None:
        self.builder = MessageBuilder()
        self.recipients_count = 0
        self.has_content = False
        self.has_sender = False
        self.expected_custom_id: str | None = None
        self.expected_unsub_url: str | None = None

    @invariant()
    def total_recipient_count_invariant(self) -> None:
        to_len = len(self.builder._payload.get("To", []))
        cc_len = len(self.builder._payload.get("Cc", []))
        bcc_len = len(self.builder._payload.get("Bcc", []))
        assert to_len + cc_len + bcc_len == self.recipients_count
        if self.expected_custom_id is not None:
            assert self.builder._payload.get("CustomID") == self.expected_custom_id
        if self.expected_unsub_url is not None:
            headers = self.builder._payload.get("Headers", {})
            assert f"<{self.expected_unsub_url}>" in headers.get("List-Unsubscribe", "")

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_recipient(self, email: str, name: str | None) -> None:
        try:
            self.builder.add_recipient(email=email, name=name)
            self.recipients_count += 1
            assert "To" in self.builder._payload
        except ValueError:
            pass

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_cc(self, email: str, name: str | None) -> None:
        try:
            self.builder.add_cc(email=email, name=name)
            self.recipients_count += 1
            assert "Cc" in self.builder._payload
        except ValueError:
            pass

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_bcc(self, email: str, name: str | None) -> None:
        try:
            self.builder.add_bcc(email=email, name=name)
            self.recipients_count += 1
            assert "Bcc" in self.builder._payload
        except ValueError:
            pass

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def set_reply_to(self, email: str, name: str | None) -> None:
        try:
            self.builder.set_reply_to(email=email, name=name)
            assert "ReplyTo" in self.builder._payload
        except ValueError:
            pass

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def set_sender(self, email: str, name: str | None) -> None:
        try:
            self.builder.set_sender(email=email, name=name)
            self.has_sender = True
            assert self.builder._payload["From"]["Email"] == SecurityGuard.normalize_domain(email.strip())
        except ValueError:
            # Expected rejection for invalid fuzzed email or sender name inputs.
            pass

    @rule(text=st.text(min_size=1, max_size=1000), html=st.text(min_size=1, max_size=1000))
    def set_text_and_html_content(self, text: str, html: str) -> None:
        self.builder.set_content(text=text, html=html)
        self.has_content = True
        assert self.builder._payload["TextPart"] == text
        assert self.builder._payload["HTMLPart"] == html

    @rule(template_id=st.integers(min_value=1, max_value=9999999))
    def set_template(self, template_id: int) -> None:
        self.builder.set_template(template_id)
        self.has_content = True
        assert self.builder._payload["TemplateID"] == template_id

    @rule(variables=st.dictionaries(st.text(max_size=20), st.text(max_size=100), max_size=10))
    def set_variables(self, variables: dict[str, str]) -> None:
        self.builder.set_variables(variables)
        assert "Variables" in self.builder._payload

    @rule(headers=st.dictionaries(st.text(min_size=1, max_size=20), st.text(max_size=50), max_size=5))
    def set_headers(self, headers: dict[str, str]) -> None:
        try:
            self.builder.set_headers(headers)
            self.expected_unsub_url = None
            assert "Headers" in self.builder._payload
        except (ValueError, TypeError):
            # Expected rejection for invalid fuzzed header names or values.
            pass

    @rule(custom_id=st.text(max_size=64))
    def set_custom_id(self, custom_id: str) -> None:
        try:
            self.builder.set_custom_id(custom_id)
            self.expected_custom_id = custom_id
        except ValueError:
            # Expected rejection for control characters in fuzzed CustomID.
            pass

    @rule(
        opens=st.sampled_from(["enabled", "disabled", None]),
        clicks=st.sampled_from(["enabled", "disabled", None]),
    )
    def set_tracking(self, opens: str | None, clicks: str | None) -> None:
        self.builder.set_tracking(opens=opens, clicks=clicks)  # type: ignore[arg-type]

    @rule(
        path_token=st.from_regex(r"[a-z0-9_-]{1,24}", fullmatch=True),
        one_click=st.booleans(),
    )
    def set_list_unsubscribe(self, path_token: str, one_click: bool) -> None:
        url = f"https://example.com/unsub/{path_token}"
        self.builder.set_list_unsubscribe(url, one_click=one_click)
        self.expected_unsub_url = url
        if one_click:
            assert self.builder._payload["Headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"

    @rule()
    def try_build_and_verify_isolation(self) -> None:
        """Build payload, verify deep-copy isolation, and verify SendPayloadBuilder roundtrip."""
        is_valid_state = (self.recipients_count > 0) and self.has_content and self.has_sender

        if is_valid_state:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                result = self.builder.build()
                result2 = self.builder.build()
                batch = SendPayloadBuilder().add_message(self.builder).build()

            assert isinstance(result, dict)
            total = len(result.get("To", [])) + len(result.get("Cc", [])) + len(result.get("Bcc", []))
            assert total == self.recipients_count
            assert batch["Messages"] == [result2]

            # Mutating returned payload must not mutate internal builder state
            if "Variables" in result:
                result["Variables"]["__mutated_probe__"] = "corrupt"
            if "Headers" in result:
                result["Headers"]["X-Mutated-Probe"] = "corrupt"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                fresh = self.builder.build()
            assert "__mutated_probe__" not in fresh.get("Variables", {})
            assert "X-Mutated-Probe" not in fresh.get("Headers", {})
        else:
            with pytest.raises(ValueError, match=r"(?i)validation failed"):
                self.builder.build()


MessageBuilderMachine.TestCase.settings = settings(
    max_examples=200,
    stateful_step_count=25,
    deadline=None,
)
TestMessageBuilder = MessageBuilderMachine.TestCase
