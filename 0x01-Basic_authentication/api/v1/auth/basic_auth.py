#!/usr/bin/env python3
'''
Basic Authentication module for the API
'''
import re
import base64
import binascii
from typing import Tuple, TypeVar
from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    '''
    Basic authentication class
    '''
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        '''
        Extracts the Base64 part of the Authorization header
        for a basic authentication
        '''
        if type(authorization_header) == str:
            try:
                res = base64.b64decode(extract_base64_authorization_header,
                                       validate=True)
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
