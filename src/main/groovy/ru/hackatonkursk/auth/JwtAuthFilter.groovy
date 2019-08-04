package ru.hackatonkursk.auth

import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.util.matcher.RequestMatcher

import javax.servlet.*
import javax.servlet.http.HttpServletRequest

class JwtAuthFilter implements Filter {

    private final AuthenticationManager authManager = new JwtAuthManager()
    private RequestMatcher requestMatcher
    private JwtService jwtService

    JwtAuthFilter(RequestMatcher requestMatcher, JwtService jwtService) {
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
                authentication = authManager.authenticate(authentication)
                SecurityContextHolder.getContext().setAuthentication(authentication)
            } else {
                throw new BadCredentialsException('Invalid token')
            }
        }
        chain.doFilter(request, response)
    }
}
