package ru.hackatonkursk.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.web.servlet.ServletComponentScan
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import ru.hackatonkursk.repo.UserRepository

@EnableWebSecurity
@ServletComponentScan("ru.hackatonkursk.auth")
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value('${logoutUrl}')
    String logoutUrl
    @Value('${whiteListedAuthUrls}')
    String[] whiteListedAuthUrls
    @Value('${originUrls}')
    String[] originUrls
    @Value('${headers}')
    String headers
    @Value('${methods}')
    String methods

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()

        http
                .csrf()
                .disable()

//        http
//                .logout()
//                .logoutUrl(logoutUrl)
//                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))

//        http
//                .authorizeRequests()
//                .antMatchers(whiteListedAuthUrls)
//                .permitAll()
    }

    @Bean
    @Primary
    UserDetailsService userDetailsServiceRepo(UserRepository users) {
        return { email -> users.findByEmail(email) }
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new NoOpPasswordEncoder()
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration()
        configuration.setAllowCredentials(true)
        configuration.setAllowedOrigins(Arrays.asList(originUrls))
        configuration.setAllowedMethods(Arrays.asList(methods))
        configuration.setAllowedHeaders(Arrays.asList(headers))
        configuration.setExposedHeaders(Arrays.asList(headers))
        def source = new UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

}
