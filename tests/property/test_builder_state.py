"""Stateful property test for the MessageBuilder.
Hypothesis will fire these rules in random sequences and check invariants.
"""

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, rule

from mailjet_rest.builders import MessageBuilder


class MessageBuilderMachine(RuleBasedStateMachine):
    @initialize()
    def init_builder(self) -> None:
        self.builder = MessageBuilder()

        # Shadow State
        self.recipients_count = 0
        self.has_content = False
        self.has_sender = False

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_recipient(self, email: str, name: str | None) -> None:
        self.builder.add_recipient(email=email, name=name)
        self.recipients_count += 1
        assert "To" in self.builder._payload

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_cc(self, email: str, name: str | None) -> None:
        self.builder.add_cc(email=email, name=name)
        self.recipients_count += 1
        assert "Cc" in self.builder._payload

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def add_bcc(self, email: str, name: str | None) -> None:
        self.builder.add_bcc(email=email, name=name)
        self.recipients_count += 1
        assert "Bcc" in self.builder._payload

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def set_reply_to(self, email: str, name: str | None) -> None:
        self.builder.set_reply_to(email=email, name=name)
        assert "ReplyTo" in self.builder._payload

    @rule(email=st.emails(), name=st.one_of(st.none(), st.text(max_size=50)))
    def set_sender(self, email: str, name: str | None) -> None:
        self.builder.set_sender(email=email, name=name)
        self.has_sender = True
        assert self.builder._payload["From"]["Email"] == email

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

    @rule(variables=st.dictionaries(st.text(), st.text(max_size=100), max_size=10))
    def set_variables(self, variables: dict) -> None:
        self.builder.set_variables(variables)
        assert "Variables" in self.builder._payload

    @rule(headers=st.dictionaries(st.text(min_size=1), st.text(max_size=50), max_size=5))
    def set_headers(self, headers: dict) -> None:
        self.builder.set_headers(headers)
        assert "Headers" in self.builder._payload

    @rule()
    def try_build(self) -> None:
        """Randomly attempt to compile the payload and verify the guardrails."""
        is_valid_state = (self.recipients_count > 0) and self.has_content and self.has_sender

        if is_valid_state:
            result = self.builder.build()
            assert isinstance(result, dict)
            # Safely count all generated recipients across lists
            total = len(result.get("To", [])) + len(result.get("Cc", [])) + len(result.get("Bcc", []))
            assert total == self.recipients_count
        else:
            with pytest.raises(ValueError) as exc_info:
                self.builder.build()
            assert "validation failed" in str(exc_info.value).lower()


TestMessageBuilder = MessageBuilderMachine.TestCase
