import re
import enum

YC_LOCKBOX_BASE_URL = "https://lockbox.api.cloud.yandex.net/lockbox/v1"
YC_LOCKBOX_PAYLOAD_BASE_URL = "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1"
YC_IAM_BASE_URL = "https://iam.api.cloud.yandex.net"
JWT_ALGORITHM = "PS256"

# regex patterns

IAM_TOKEN_REGEX = re.compile(r"t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}")
OAUTH_TOKEN_REGEX = re.compile(r"y[0-3]_[a-zA-Z0-9_-]+")
LEGACY_OAUTH_TOKEN_REGEX = re.compile(r"AQ[a-zA-Z0-9_-]+")


class RpcError(int, enum.Enum):
    """This class convert grpc digit codes to messages."""

    CANCELLED = 1
    UNKNOWN = 2
    INVALID_ARGUMENT = 3
    DEADLINE_EXCEEDED = 4
    NOT_FOUND = 5
    ALREADY_EXISTS = 6
    PERMISSION_DENIED = 7
    RESOURCE_EXHAUSTED = 8
    FAILED_PRECONDITION = 9
    ABORTED = 10
    OUT_OF_RANGE = 11
    NOT_IMPLEMENTED = 12
    INTERNAL = 13
    UNAVAILABLE = 14
    DATA_LOSS = 15
    UNAUTHENTICATED = 16
