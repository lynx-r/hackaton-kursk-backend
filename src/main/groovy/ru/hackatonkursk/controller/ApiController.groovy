package ru.hackatonkursk.controller

import groovy.json.JsonSlurper
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.domain.User

@RestController()
@RequestMapping('api')
class ApiController {

    private JwtService jwtService

    ApiController(JwtService jwtService) {
        this.jwtService = jwtService
    }

    @GetMapping('')
    hello() {
        return 'hello'
    }

    @GetMapping('/public/test')
    publicTest() {
        return 'public test'
    }

    @GetMapping('/metrics')
    @PreAuthorize('hasRole("ADMIN")')
    metrics(Authentication authentication) {
        println(authentication)
        InputStream inputStream = getClass().getResourceAsStream('/data/metrics.json')
        return new JsonSlurper().parse(inputStream)
    }

    @GetMapping('auth/login')
    @PreAuthorize('hasAnyRole("GUEST", "ADMIN")')
    login(Authentication authentication) {
        def user = authentication.principal as User
        def token = jwtService.generateToken(user.username, user.authorities)
        return [token: token]
    }

}
