package ru.hackatonkursk.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties('appclients')
class ApplicationClientsProperties {

    List<ApplicationClient> clients = new ArrayList<>()

    static class ApplicationClient {
        private String username
        private String password
        private String[] roles
    }
}
