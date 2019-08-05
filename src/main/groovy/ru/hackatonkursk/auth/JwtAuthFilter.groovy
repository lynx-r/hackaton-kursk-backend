package ru.hackatonkursk.auth

import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.util.matcher.OrRequestMatcher

import javax.servlet.*
import javax.servlet.http.HttpServletRequest

class JwtAuthFilter implements Filter {

    private OrRequestMatcher requestMatcher
    private JwtService jwtService

    JwtAuthFilter(OrRequestMatcher requestMatcher, JwtService jwtService) {
        this.jwtService = jwtService
        this.requestMatcher = requestMatcher
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = request as HttpServletRequest
        if (requestMatcher.matches(req)) {
            String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION)
            def token = JwtService.getTokenFromHeader(authHeader)
            if (!token.isEmpty()) {
                def claim = jwtService.verifySignedJWT(token)
                def authentication = JwtService.getUsernamePasswordAuthenticationToken(claim)
                SecurityContextHolder.getContext().setAuthentication(authentication)
            } else {
                throw new BadCredentialsException('Invalid token')
            }
        }
        chain.doFilter(request, response)
    }
}
