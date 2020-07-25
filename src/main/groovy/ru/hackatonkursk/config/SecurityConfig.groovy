package ru.hackatonkursk.config


import org.springframework.boot.web.servlet.ServletComponentScan
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
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import ru.hackatonkursk.service.JwtService
import ru.hackatonkursk.repo.UserRepository

@EnableWebSecurity
@ServletComponentScan("ru.hackatonkursk.auth")
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
                .cors()

        http
                .csrf()
                .disable()

        http
                .logout()
                .logoutUrl(authSecurityConfig.logoutUrl)
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))

        http
                .authorizeRequests()
                .antMatchers(authSecurityConfig.whiteListedAuthUrls)
                .permitAll()
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
        println("????" + authSecurityConfig.originUrls + " " + authSecurityConfig.methods)
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(Arrays.asList(authSecurityConfig.originUrls));
        configuration.setAllowedMethods(Arrays.asList(authSecurityConfig.methods));
        configuration.setAllowedHeaders(Arrays.asList(authSecurityConfig.headers));
        configuration.setExposedHeaders(Arrays.asList(authSecurityConfig.headers));
        def source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
