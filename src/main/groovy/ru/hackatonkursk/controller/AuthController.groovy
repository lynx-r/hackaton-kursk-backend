package ru.hackatonkursk.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.hackatonkursk.service.JwtService
import ru.hackatonkursk.domain.User

@RestController()
@RequestMapping('api/auth')
class AuthController {

    private JwtService jwtService

    AuthController(JwtService jwtService) {
        this.jwtService = jwtService
    }

    @PostMapping('token')
    @PreAuthorize('hasAnyRole("GUEST", "ADMIN")')
    getToken(Authentication authentication) {
        def user = authentication.principal as User
        def token = jwtService.generateToken(user.username, user.authorities)
        return [token: token]
    }

    @GetMapping('authenticated')
    @PreAuthorize('isAuthenticated()')
    isAuthenticated() {
        return [isLoggedIn: true]
    }

}
