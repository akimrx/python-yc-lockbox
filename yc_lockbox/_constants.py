import re

YC_LOCKBOX_BASE_URL = "https://lockbox.api.cloud.yandex.net/lockbox/v1"
YC_LOCKBOX_PAYLOAD_BASE_URL = "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1"
YC_IAM_BASE_URL = "https://iam.api.cloud.yandex.net"
JWT_ALGORITHM = "PS256"

# regex patterns

IAM_TOKEN_REGEX = re.compile(r"t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}")
OAUTH_TOKEN_REGEX = re.compile(r"y[0-3]_[a-zA-Z0-9_-]+")
LEGACY_OAUTH_TOKEN_REGEX = re.compile(r"AQ[a-zA-Z0-9_-]+")
