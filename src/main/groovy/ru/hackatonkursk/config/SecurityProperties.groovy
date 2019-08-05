package ru.hackatonkursk.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration

@Configuration
class SecurityProperties {

    @Value('${tokenExpirationMinutes:60}')
    Integer tokenExpirationMinutes

    @Value('${tokenIssuer:workingbit-example.com}')
    String tokenIssuer

    @Value('${tokenSecret:secret}')
    // length minimum 256 bites
    String tokenSecret

    @Value('${whiteListedAuthUrls}')
    String[] whiteListedAuthUrls
    @Value('${jwtTokenMatchUrls}')
    String[] jwtTokenMatchUrls
    @Value('${originUrl}')
    String originUrl
    @Value('${headers}')
    String headers
    @Value('${methods}')
    String methods
    @Value('${exposedHeaders}')
    String exposedHeaders

    @Value('${loginUrl}')
    String loginUrl
    @Value('${logoutUrl}')
    String logoutUrl

    @Value('${realmKey}')
    String realmKey
    @Value('${realmName}')
    String realmName

}
