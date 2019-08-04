package ru.hackatonkursk.config

import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

class CorsConfigurationSourceAdapter {
    private final String clientUrl
    private final String[] headers
    private final String[] methods
    private final String[] exposedHeaders

    CorsConfigurationSourceAdapter(String clientUrl, String headers, String methods, String exposedHeaders) {
        this.clientUrl = clientUrl
        this.headers = headers.split(",")
        this.methods = methods.split(",")
        this.exposedHeaders = exposedHeaders.split(',')
    }

    CorsConfigurationSource corsFilter(boolean allowCredentials) {
        CorsConfiguration config = new CorsConfiguration()
        config.addAllowedOrigin(clientUrl)
        for (String header : headers) {
            config.addAllowedHeader(header)
        }
        for (String method : methods) {
            config.addAllowedMethod(method)
        }
        for (String header : exposedHeaders) {
            config.addExposedHeader(header)
        }
        config.setAllowCredentials(allowCredentials)
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }
}
