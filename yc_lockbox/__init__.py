"""
Yandex Cloud Lockbox client.

MIT License

Copyright (c) 2024 Akim Faskhutdinov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from yc_lockbox._lockbox import YandexLockboxClient
from yc_lockbox._models import (
    Secret,
    INewSecretPayloadEntry,
    INewSecret,
    INewSecretVersion,
    IUpdateSecret,
    Operation,
    YandexCloudError,
)

__version__ = "0.1.3"
__author__ = "Akim Faskhutdinov"
__author_email__ = "akimstrong@yandex.ru"
__license__ = "MIT"
__url__ = "https://github.com/akimrx/python-yc-lockbox"

__all__ = [
    "Secret",
    "INewSecretPayloadEntry",
    "INewSecret",
    "INewSecretVersion",
    "IUpdateSecret",
    "YandexLockboxClient",
    "Operation",
    "YandexCloudError",
]
