class LockboxError(Exception):
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, **kwargs)


class InvalidCredentials(LockboxError):
    def __init__(self, message: str = "Invalid credentials", **kwargs) -> None:
        super().__init__(message, **kwargs)


class BadCredentials(LockboxError):
    def __init__(self, message: str = "Bad credentials.", **kwargs) -> None:
        super().__init__(message, **kwargs)
