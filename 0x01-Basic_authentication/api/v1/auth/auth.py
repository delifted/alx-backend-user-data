#!/usr/bin/env python3
'''
Authentication file
'''
from flask import request
from typing import List, TypeVar


class Auth:
    '''
    Class Auth
    '''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''
        Checks if a path requires authentication
        '''
        return False

    def authorization_header(self, request=None) -> str:
        '''
        Gets the authorization header field from the request
        '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''
        Gets active user from the request
        '''
        return None
