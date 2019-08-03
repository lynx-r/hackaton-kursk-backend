package ru.hackatonkursk.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import ru.hackatonkursk.auth.JwtService
import ru.hackatonkursk.domain.User

@RestController
class ApiController {

    private JwtService jwtService

    ApiController(JwtService jwtService) {
        this.jwtService = jwtService
    }

    @GetMapping('/')
    hello() {
        return 'hello'
    }

    @GetMapping('/public/test')
    publicTest() {
        return 'public test'
    }

    @GetMapping('/metrics/m1')
    @PreAuthorize('hasRole("ADMIN")')
    metrics(Authentication authentication) {
        println(authentication)
        return 'metrics are protected'
    }

    @GetMapping('/login')
    @PreAuthorize('hasAnyRole("GUEST", "ADMIN")')
    login(Authentication authentication) {
        println(authentication)
        print('auth!')
        def user = authentication.principal as User
        println(user)
        println(user.authorities)
        def token = jwtService.generateToken(user.username, user.authorities)
        return token
    }

}
