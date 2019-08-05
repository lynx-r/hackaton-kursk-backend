package ru.hackatonkursk.config

import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler
import org.springframework.security.web.authentication.www.DigestAuthUtils
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.authentication.www.NonceExpiredException
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.web.cors.CorsConfigurationSource
import ru.hackatonkursk.auth.JwtAuthFilter
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.repo.UserRepository

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig extends WebSecurityConfigurerAdapter {

    private JwtService jwtService
    private SecurityProperties authSecurityConfig

    SecurityConfig(
            JwtService jwtService,
            SecurityProperties authSecurityConfig
    ) {
        this.authSecurityConfig = authSecurityConfig
        this.jwtService = jwtService
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtAuthFilter jwtAuthFilter = getJwtAuthFilter()

        http
                .exceptionHandling()
                .and()
                .sessionManagement()
                .and()
                .securityContext()
                .and()
                .requestCache()
                .and()
                .csrf()
                .disable()
                .logout()
                .logoutUrl(authSecurityConfig.logoutUrl)
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))

        http
                .authorizeRequests()
                .antMatchers(authSecurityConfig.whiteListedAuthUrls)
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(jwtAuthFilter, AnonymousAuthenticationFilter.class)

        http
                .antMatcher('/**')
                .cors()
                .configurationSource(corsSource())
    }

    @Bean
    FilterRegistrationBean<DigestAuthenticationFilter> digestAuthenticationFilterFilterRegistrationBean(
            UserDetailsService userDetailsService
    ) {
        FilterRegistrationBean<DigestAuthenticationFilter> registrationBean = new FilterRegistrationBean<>()

        registrationBean.setFilter(digestAuthenticationFilter(userDetailsService))
        registrationBean.addUrlPatterns(authSecurityConfig.loginUrl)

        return registrationBean
    }

    DigestAuthenticationFilter digestAuthenticationFilter(UserDetailsService userDetailsService) {
        DigestAuthenticationFilter digestAuthenticationFilter = new DigestAuthenticationFilter()
        digestAuthenticationFilter.setUserDetailsService(userDetailsService)
        digestAuthenticationFilter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint())
        return digestAuthenticationFilter
    }

    @Bean
    DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        DigestAuthenticationEntryPoint digestAuthenticationEntryPoint = new DigestAuthenticationEntryPoint() {
            @Override
            void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                HttpServletResponse httpResponse = (HttpServletResponse) response

                // compute a nonce (do not use remote IP address due to proxy farms)
                // format of nonce is:
                // base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
                long expiryTime = System.currentTimeMillis() + (nonceValiditySeconds * 1000)
                String signatureValue = DigestAuthUtils.md5Hex(expiryTime + ":" + key)
                String nonceValue = expiryTime + ":" + signatureValue
                String nonceValueBase64 = new String(Base64.getEncoder().encode(nonceValue.getBytes()))

                // qop is quality of protection, as defined by RFC 2617.
                // we do not use opaque due to IE violation of RFC 2617 in not
                // representing opaque on subsequent requests in same session.
                String authenticateHeader = "X-Digest realm=\"${realmName}\", qop=\"auth\", nonce=\"${nonceValueBase64}\""

                if (authException instanceof NonceExpiredException) {
                    authenticateHeader = "${authenticateHeader}, stale=\"true\""
                }

                httpResponse.addHeader("WWW-Authenticate", authenticateHeader)
                httpResponse.sendError(HttpStatus.UNAUTHORIZED.value(),
                        HttpStatus.UNAUTHORIZED.getReasonPhrase())
            }
        }
        digestAuthenticationEntryPoint.setKey(authSecurityConfig.realmKey)
        digestAuthenticationEntryPoint.setRealmName(authSecurityConfig.realmName)
        return digestAuthenticationEntryPoint
    }

    @Bean
    @Primary
    UserDetailsService userDetailsRepository(UserRepository users) {
        return { email -> users.findByEmail(email) }
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new NoOpPasswordEncoder()
    }

    private CorsConfigurationSource corsSource() {
        return new CorsConfigurationSourceAdapter(
                authSecurityConfig.originUrl,
                authSecurityConfig.headers,
                authSecurityConfig.methods,
                authSecurityConfig.exposedHeaders
        ).corsFilter(false)
    }

    private JwtAuthFilter getJwtAuthFilter() {
        def matchers = authSecurityConfig.jwtTokenMatchUrls.collect { new AntPathRequestMatcher(it) }
        def orMatcher = new OrRequestMatcher(matchers)
        def jwtAuthFilter = new JwtAuthFilter(orMatcher, jwtService)
        jwtAuthFilter
    }

}
