package ru.hackatonkursk.auth

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException

class JwtAuthManager implements AuthenticationManager {
    @Override
    Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication
    }
}
