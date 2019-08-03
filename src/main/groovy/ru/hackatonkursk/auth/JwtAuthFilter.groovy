package ru.hackatonkursk.auth

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.RequestMatcher

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.util.function.Function

class JwtAuthFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationManager authManager = new JwtAuthManager()
    private Function<HttpServletRequest, Authentication> jwtAuthConverter

    JwtAuthFilter(RequestMatcher requiresAuthenticationRequestMatcher, JwtService jwtService) {
        super(requiresAuthenticationRequestMatcher)
        this.jwtAuthConverter = new JwtAuthConverter(jwtService)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        HttpServletRequest req = request as HttpServletRequest
        return this.jwtAuthConverter.apply(req)
    }
}
