package ru.hackatonkursk.config


import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.PropertySource
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import ru.hackatonkursk.auth.JwtAuthFilter
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.repo.UserRepository

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
        http.cors().disable()

        http
//        .addFilterBefore(corsFilter(), SessionManagementFilter.class) //adds your custom CorsFilter
                .authorizeRequests()
                .antMatchers(whiteListedAuthUrls)
                .permitAll()
                .antMatchers('/login')
                .authenticated()
                .and()
                .httpBasic()
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

//    @Bean
//    authFilter() {
//        FilterRegistration<BasicAuthenticationFilter> filterRegistration = new FilterRegistrationBean<>()
//        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter()
//    }

    @Bean
    UserDetailsService userDetailsRepository(UserRepository users) {
        return { email -> users.findByEmail(email) }
    }

//  private CorsFilter corsFilter() {
//    return new CorsFilterAdapter(
//        appProperties.getOriginUrl(),
//        appProperties.getHeaders(),
//        appProperties.getMethods())
//        .corsFilter();
//  }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }
}
