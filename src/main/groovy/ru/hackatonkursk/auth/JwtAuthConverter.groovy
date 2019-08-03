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
    Authentication apply(HttpServletRequest serverWebExchange) {
        def header = jwtService.getAuthorizationPayload(serverWebExchange)
        if (jwtService.matchBearerLength(header)) {
            def value = jwtService.getBearerValue(header)
            if (!value.isEmpty()) {
                def claim = jwtService.verifySignedJWT(value)
                return jwtService.getUsernamePasswordAuthenticationToken(claim)
            }
        }
        throw new BadCredentialsException()
    }
}
