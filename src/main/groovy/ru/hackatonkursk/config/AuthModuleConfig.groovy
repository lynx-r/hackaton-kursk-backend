package ru.hackatonkursk.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.PropertySource

@Configuration
@PropertySource('classpath:authConfig.yml')
class AuthModuleConfig {

    @Value('${tokenExpirationMinutes:60}')
    Integer tokenExpirationMinutes

    @Value('${tokenIssuer:workingbit-example.com}')
    String tokenIssuer

    @Value('${tokenSecret:secret}')
    // length minimum 256 bites
    String tokenSecret

    @Value('${whiteListedAuthUrls}')
    String[] whiteListedAuthUrls
    @Value('${jwtTokenMatchUrl}')
    String jwtTokenMatchUrl
    @Value('${originUrl}')
    String originUrl
    @Value('${headers}')
    String headers
    @Value('${methods}')
    String methods
    @Value('${exposedHeaders}')
    String exposedHeaders

}
