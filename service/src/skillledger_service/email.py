import resend


def send_otp_email(email: str, code: str, api_key: str, from_email: str) -> None:
    """Send OTP verification code via Resend.

    Plain text email with subject format: "SkillLedger verification code: XXXXXX"
    """
    resend.api_key = api_key
    params: resend.Emails.SendParams = {
        "from": from_email,
        "to": [email],
        "subject": f"SkillLedger verification code: {code}",
        "text": (
            f"Your SkillLedger verification code is: {code}\n\n"
            "This code expires in 10 minutes.\n\n"
            "If you did not request this code, you can safely ignore this email."
        ),
    }
    resend.Emails.send(params)
