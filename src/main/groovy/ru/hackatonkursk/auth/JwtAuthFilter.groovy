package ru.hackatonkursk.auth

import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.stereotype.Component
import ru.hackatonkursk.service.JwtService

import javax.servlet.*
import javax.servlet.annotation.WebFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
@WebFilter(["/api/protected/metrics**", "/api/auth/authenticated"])
class JwtAuthFilter extends AbstractAuthenticationProcessingFilter {

    private static final String BEARER = "Bearer "

    private JwtService jwtService
    private UserDetailsService userDetailsService

    JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        super(new OrRequestMatcher(
                new AntPathRequestMatcher("/api/protected/metrics**"),
                new AntPathRequestMatcher("/api/auth/authenticated"))
        )
        this.jwtService = jwtService
        this.userDetailsService = userDetailsService
        setAuthenticationManager(authenticationManager())
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION)
        def token = getTokenFromHeader(authHeader)
        if (!token.isEmpty()) {
            def claim = jwtService.verifySignedJWT(token)
            return JwtService.getUsernamePasswordAuthenticationToken(claim)
        } else {
            throw new BadCredentialsException('Invalid token')
        }
    }

    private static AuthenticationManager authenticationManager() {
        def daoAuthProvider = new DaoAuthenticationProvider()
        return new ProviderManager(daoAuthProvider)
    }

    private static String getTokenFromHeader(String authHeader) {
        if (authHeader != null) {
            def matchBearerLength = authHeader.length() > BEARER.length()
            if (matchBearerLength) {
                return authHeader.substring(BEARER.length())
            }
        }
        return ""
    }

}
