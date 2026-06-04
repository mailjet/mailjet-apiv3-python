from typing import Any
import sys
import base64
import atheris


with atheris.instrument_imports():
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.errors import ValidationError

def generate_valid_payload(fdp: atheris.FuzzedDataProvider) -> dict:
    payload: dict[str, Any] = {"Messages": []}

    # Fuzz SandboxMode at the root payload level
    if fdp.ConsumeBool():
        payload["SandboxMode"] = fdp.ConsumeBool()

    num_messages = fdp.ConsumeIntInRange(1, 3)

    for _ in range(num_messages):
        msg: dict[str, Any] = {}
        msg["From"] = {
            "Email": fdp.ConsumeUnicodeNoSurrogates(15) + "@example.com",
            "Name": fdp.ConsumeUnicodeNoSurrogates(15) if fdp.ConsumeBool() else None
        }

        msg["To"] = [
            {
                "Email": fdp.ConsumeUnicodeNoSurrogates(15) + "@example.com",
                "Name": fdp.ConsumeUnicodeNoSurrogates(15) if fdp.ConsumeBool() else None
            }
            for _ in range(fdp.ConsumeIntInRange(1, 2))
        ]

        if fdp.ConsumeBool():
            msg["Cc"] = [{"Email": fdp.ConsumeUnicodeNoSurrogates(10) + "@ex.com"}]
        if fdp.ConsumeBool():
            msg["Bcc"] = [{"Email": fdp.ConsumeUnicodeNoSurrogates(10) + "@ex.com"}]
        if fdp.ConsumeBool():
            msg["TemplateID"] = fdp.ConsumeInt(1000000)
            msg["TemplateLanguage"] = fdp.ConsumeBool()

        # Add Tracing, Tracking, and Custom Identity Fuzzing
        if fdp.ConsumeBool():
            msg["CustomID"] = fdp.ConsumeUnicodeNoSurrogates(30)
        if fdp.ConsumeBool():
            msg["EventPayload"] = fdp.ConsumeUnicodeNoSurrogates(50)
        if fdp.ConsumeBool():
            msg["TrackOpens"] = fdp.PickValueInList(["enabled", "disabled", "account_default", fdp.ConsumeUnicodeNoSurrogates(5)])

        if fdp.ConsumeBool():
            fuzzed_binary = fdp.ConsumeBytes(150)
            try:
                b64_data = base64.b64encode(fuzzed_binary).decode('utf-8')
            except Exception:
                b64_data = "invalid_b64"

            msg["Attachments"] = [{
                "ContentType": "text/plain",
                "Filename": fdp.ConsumeUnicodeNoSurrogates(10) + ".txt",
                "Base64Content": b64_data
            }]

        payload["Messages"].append(msg)

    return payload


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return
    fdp = atheris.FuzzedDataProvider(data)

    target = fdp.ConsumeIntInRange(0, 1)

    if target == 0:
        builder = MessageBuilder()
        try:
            # Parse our fuzzed structural dictionary
            payload_dict = generate_valid_payload(fdp)
            for msg in payload_dict.get("Messages", []):
                builder.set_sender(msg.get("From", {}).get("Email", ""), msg.get("From", {}).get("Name"))

                for to in msg.get("To", []):
                    builder.add_recipient(to.get("Email", ""), to.get("Name"))
                for cc in msg.get("Cc", []):
                    builder.add_cc(cc.get("Email", ""), cc.get("Name"))
                for bcc in msg.get("Bcc", []):
                    builder.add_bcc(bcc.get("Email", ""), bcc.get("Name"))

                if "Subject" in msg:
                    builder.set_subject(msg["Subject"])
                if "TextPart" in msg:
                    builder.set_content(text=msg["TextPart"])
                if "HTMLPart" in msg:
                    builder.set_content(html=msg["HTMLPart"])
                if "TemplateID" in msg:
                    builder.set_template(msg["TemplateID"])

                # NEW: Ensure fuzzed attachments are injected into the builder state
                if "Attachments" in msg:
                    builder._msg["Attachments"] = msg["Attachments"]

                if "Variables" in msg:
                    builder._msg["Variables"] = msg["Variables"]

            builder.build()
        except (ValueError, ValidationError, TypeError):
            # Expected for malformed fuzzed inputs; keep fuzzing subsequent cases.
            pass
    else:
        t_builder = TemplateContentBuilder()
        try:
            t_builder.set_meta(fdp.ConsumeUnicodeNoSurrogates(10), fdp.ConsumeUnicodeNoSurrogates(10))
            t_builder.set_content(
                text=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                html=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                mjml=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None
            )
            t_builder.build()
        except (ValueError, ValidationError, TypeError):
            # Expected for malformed fuzz inputs; ignore so the fuzzer can continue exploring.
            pass

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
