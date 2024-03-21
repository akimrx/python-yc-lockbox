class BaseException(Exception):
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, **kwargs)


class InvalidCredentials(BaseException):
    def __init__(self, message: str = "Invalid credentials", **kwargs) -> None:
        super().__init__(message, **kwargs)


class BadCredentials(BaseException):
    def __init__(self, message: str = "Bad credentials.", **kwargs) -> None:
        super().__init__(message, **kwargs)
