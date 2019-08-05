package ru.hackatonkursk.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController()
@RequestMapping('api/public')
class PublicController {

    @GetMapping('')
    getGreeting() {
        return [greeting: 'Welcome!']
    }

    @GetMapping('test')
    getPublicTest() {
        return [message: 'Test public api']
    }

}
