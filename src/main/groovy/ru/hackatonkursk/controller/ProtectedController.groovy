package ru.hackatonkursk.controller

import groovy.json.JsonSlurper
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController()
@RequestMapping('api/protected')
class ProtectedController {

    @GetMapping('metrics')
    @PreAuthorize('hasRole("ADMIN")')
    getMetrics(Authentication authentication) {
        println(authentication)
        InputStream inputStream = getClass().getResourceAsStream('/data/metrics.json')
        return new JsonSlurper().parse(inputStream)
    }

}
