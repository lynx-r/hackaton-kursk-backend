package ru.hackatonkursk.config

import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.web.cors.CorsConfigurationSource
import ru.hackatonkursk.auth.JwtAuthFilter
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.repo.UserRepository

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
        http
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
                .addFilterBefore(getJwtAuthFilter(), AnonymousAuthenticationFilter.class)

        http
                .antMatcher('/**')
                .cors()
                .configurationSource(corsSource())
    }

    @Bean
    FilterRegistrationBean<DigestAuthenticationFilter> digestAuthenticationFilter(
            UserDetailsService userDetailsService
    ) {
        FilterRegistrationBean<DigestAuthenticationFilter> registrationBean = new FilterRegistrationBean<>()

        DigestAuthenticationFilter digestAuthenticationFilter = new DigestAuthenticationFilter()
        digestAuthenticationFilter.setUserDetailsService(userDetailsService)
        digestAuthenticationFilter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint())

        registrationBean.setFilter(digestAuthenticationFilter)
        registrationBean.addUrlPatterns(authSecurityConfig.loginUrl)
        return registrationBean
    }

    /**
     * Returns entry point for digest authentication. It returns a header with X-Digest to prevent a browser popup
     * @return
     */
    @Bean
    DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        def digestAuthenticationEntryPoint = new BrowserDigestAuthenticationEntryPoint()
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
        return jwtAuthFilter
    }

}
