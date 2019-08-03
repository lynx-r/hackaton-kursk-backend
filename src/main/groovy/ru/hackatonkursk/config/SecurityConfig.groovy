package ru.hackatonkursk.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.PropertySource
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler
import org.springframework.security.web.authentication.www.DigestAuthUtils
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.authentication.www.NonceExpiredException
import ru.hackatonkursk.auth.JwtAuthFilter
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.repo.UserRepository

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
//@Configuration
@PropertySource(value = "classpath:/application.properties")
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value('${whiteListedAuthUrls}')
    private String[] whiteListedAuthUrls
    @Value('${jwtTokenMatchUrls}')
    private String[] jwtTokenMatchUrls

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
        http
                .logout()
                .logoutUrl('/api/logout')
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
        http
                .exceptionHandling()
        http
                .sessionManagement()
        http
                .securityContext()

        http
//        .authorizeRequests()
//        .antMatchers(jwtTokenMatchUrls)
                .requestCache()

        http
//        .addFilterBefore(corsFilter(), SessionManagementFilter.class) //adds your custom CorsFilter
                .authorizeRequests()
                .antMatchers(whiteListedAuthUrls)
                .permitAll()
                .anyRequest()
                .authenticated()
//                .antMatchers('/login')
//                .authenticated()
//                .and()
//                .httpBasic()
    }

    @Bean
    FilterRegistrationBean<JwtAuthFilter> jwtFilter(
            JwtService jwtService
    ) {
        FilterRegistrationBean<JwtAuthFilter> registrationBean = new FilterRegistrationBean<>()

        registrationBean.setFilter(new JwtAuthFilter(jwtService))
        registrationBean.addUrlPatterns(jwtTokenMatchUrls)

        return registrationBean
    }

    @Bean
    FilterRegistrationBean<DigestAuthenticationFilter> digestAuthenticationFilterFilterRegistrationBean(
            UserDetailsService userDetailsService
    ) {
        FilterRegistrationBean<DigestAuthenticationFilter> registrationBean = new FilterRegistrationBean<>()

        registrationBean.setFilter(digestAuthenticationFilter(userDetailsService))
        registrationBean.addUrlPatterns('/api/auth/login')

        return registrationBean
    }

    DigestAuthenticationFilter digestAuthenticationFilter(UserDetailsService userDetailsService) {
        DigestAuthenticationFilter digestAuthenticationFilter = new DigestAuthenticationFilter() {
            @Override
            void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) req
                HttpServletResponse response = (HttpServletResponse) res

                String header = request.getHeader("Authorization")
                if (header == null) {
                    SecurityContextHolder.getContext().setAuthentication(null)
                    getAuthenticationEntryPoint().commence(request, response, new BadCredentialsException('Invalid header'))
                    return
                }
                super.doFilter(req, res, chain)
            }
        }
        digestAuthenticationFilter.setUserDetailsService(userDetailsService)
        digestAuthenticationFilter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint())
//        digestAuthenticationFilter.setPasswordAlreadyEncoded(true)
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
        digestAuthenticationEntryPoint.setKey('acegi')
        digestAuthenticationEntryPoint.setRealmName('Contacts Realm via Digest Authentication')
        return digestAuthenticationEntryPoint
    }

//    @Bean
//    authFilter() {
//        FilterRegistration<BasicAuthenticationFilter> filterRegistration = new FilterRegistrationBean<>()
//        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter()
//    }

    @Bean
    @Primary
    UserDetailsService userDetailsRepository(UserRepository users) {
        return { email -> users.findByEmail(email) }
    }

//  private CorsFilter corsFilter() {
//    return new CorsFilterAdapter(
//        appProperties.getOriginUrl(),
//        appProperties.getHeaders(),
//        appProperties.getMethods())
//        .corsFilter()
//  }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new NoOpPasswordEncoder()
    }
}
