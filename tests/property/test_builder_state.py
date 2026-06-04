import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize

from mailjet_rest.builders import MessageBuilder

class MessageBuilderMachine(RuleBasedStateMachine):
    """
    Stateful property test for the MessageBuilder.
    Hypothesis will fire these rules in random sequences and check invariants.
    """

    @initialize()
    def init_builder(self) -> None:
        self.builder = MessageBuilder()

        # Shadow State
        self.recipients_count = 0
        self.has_content = False
        self.has_sender = False

    @rule(email=st.emails(), name=st.text(max_size=50))
    def add_recipient(self, email: str, name: str) -> None:
        self.builder.add_recipient(email=email, name=name)
        self.recipients_count += 1

        assert "To" in self.builder._msg
        assert len(self.builder._msg["To"]) == self.recipients_count

    @rule(email=st.emails(), name=st.text(max_size=50))
    def set_sender(self, email: str, name: str) -> None:
        self.builder.set_sender(email=email, name=name)
        self.has_sender = True

        assert self.builder._msg["From"]["Email"] == email

    @rule(text=st.text(max_size=1000))
    def set_text_content(self, text: str) -> None:
        self.builder.set_content(text=text)
        self.has_content = True

        assert self.builder._msg["TextPart"] == text

    @rule(template_id=st.integers(min_value=1, max_value=9999999))
    def set_template(self, template_id: int) -> None:
        self.builder.set_template(template_id)
        self.has_content = True

        assert self.builder._msg["TemplateID"] == template_id

    @rule()
    def try_build(self) -> None:
        """
        Randomly attempt to compile the payload and verify the guardrails.
        """
        # We must also require a Sender before expecting build() to pass
        is_valid_state = (self.recipients_count > 0) and self.has_content and self.has_sender

        if is_valid_state:
            # If the state is complete, it MUST succeed
            result = self.builder.build()
            assert isinstance(result, dict)
            assert len(result["To"]) == self.recipients_count
        else:
            # If the state is incomplete, it MUST fail safely with a validation error
            with pytest.raises(ValueError) as exc_info:
                self.builder.build()

            error_msg = str(exc_info.value).lower()
            assert "validation failed" in error_msg

# Expose the state machine to pytest
TestMessageBuilder = MessageBuilderMachine.TestCase
