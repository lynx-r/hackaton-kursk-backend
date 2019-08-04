package ru.hackatonkursk.auth


import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication

import javax.servlet.http.HttpServletRequest
import java.util.function.Function

class JwtAuthConverter implements Function<HttpServletRequest, Authentication> {

    private final JwtService jwtService

    JwtAuthConverter(JwtService jwtService) {
        this.jwtService = jwtService
    }

    @Override
    Authentication apply(HttpServletRequest req) {
        throw new BadCredentialsException()
    }
}
