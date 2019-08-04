package ru.hackatonkursk.auth

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.util.matcher.RequestMatcher

import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import java.util.function.Function

class JwtAuthFilter implements Filter {

    private final AuthenticationManager authManager = new JwtAuthManager()
    private Function<HttpServletRequest, Authentication> jwtAuthConverter
    private RequestMatcher requestMatcher

    JwtAuthFilter(RequestMatcher requestMatcher, JwtService jwtService) {
        this.requestMatcher = requestMatcher
        this.jwtAuthConverter = new JwtAuthConverter(jwtService)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = request as HttpServletRequest
        if (requestMatcher.matches(req)) {
            def authentication = this.jwtAuthConverter.apply(req)
            authentication = authManager.authenticate(authentication)
            SecurityContextHolder.getContext().setAuthentication(authentication)
        }
        chain.doFilter(request, response)
    }
}
