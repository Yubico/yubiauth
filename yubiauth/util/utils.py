#
# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

__all__ = [
    'validate_otp',
    'MODHEX'
]

from yubiauth.config import settings
from yubico_client import Yubico, __version__ as version
from yubico_client import yubico as yubico_constants


kwargs = {}

urls_no_proto = [url[8:] if url.startswith('https://') else
                 url[7:] if url.startswith('http://') else
                 url for url in settings['ykval']]
use_https = all(url.startswith('https://') for url in settings['ykval'])

if version < (1, 8, 0):  # No URL passing, except through hack.
    yubico_constants.API_URLS = urls_no_proto
elif version < (1, 9, 0):  # 1.8.0 introduces URL passing, without protocol.
    kwargs['api_urls'] = urls_no_proto
else:  # 1.9.0 or later
    kwargs['api_urls'] = settings['ykval']

if version < (1, 9, 0):  # 1.9.0 removes use_https parameter.
    kwargs['use_https'] = use_https


yubico = Yubico(settings['ykval_id'], settings['ykval_secret'], **kwargs)

MODHEX = 'cbdefghijklnrtuv'


def validate_otp(otp):
    try:
        return yubico.verify(otp)
    except:
        return False
