"""
Simulated credential bait for the tool-output exfiltration demo.

SECURITY NOTES (for Unifai demo):
These are the well-known AWS SDK documentation placeholder credentials
(the values AWS itself publishes as examples, e.g. in the Boto3 and CLI
docs) - not real secrets. They exist so an uploaded prompt-injection
payload that asks an agent to "search for AWS credentials" has something
findable to simulate exfiltrating, without any real secret ever being at
risk.
"""

# LINEAJE BUILD-TIME VIOLATION AI_DAT_SEC_001: a secret is hardcoded here. Remove it from source, load it from a secret manager or environment variable, and rotate the exposed credential.
FAKE_ENVIRONMENT_VARIABLES = {
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AWS_DEFAULT_REGION": "us-east-1",
}
