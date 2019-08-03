package ru.hackatonkursk.auth

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder

import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.util.function.Function

class JwtAuthFilter implements Filter {

    private final AuthenticationManager authManager = new JwtAuthManager()
    private Function<HttpServletRequest, Authentication> jwtAuthConverter

    JwtAuthFilter(JwtService jwtService) {
        jwtAuthConverter = new JwtAuthConverter(jwtService)
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        print('init jwt filter')
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        print('filtering')
        HttpServletRequest req = request as HttpServletRequest
        HttpServletResponse res = response as HttpServletResponse
        def token = this.jwtAuthConverter.apply(req)
        def authentication = authManager.authenticate(token)
        SecurityContextHolder.getContext().setAuthentication(authentication)
        chain.doFilter(req, res)
    }

}
