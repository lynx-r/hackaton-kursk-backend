package ru.hackatonkursk.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.PropertySource

@Configuration
@PropertySource('classpath:moduleConfig.yml')
class AuthModuleConfig {

    @Value('${tokenExpirationMinutes:60}')
    Integer tokenExpirationMinutes

    @Value('${tokenIssuer:workingbit-example.com}')
    String tokenIssuer

    @Value('${tokenSecret:secret}')
    // length minimum 256 bites
    String tokenSecret
}
