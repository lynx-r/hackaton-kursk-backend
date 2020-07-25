package ru.hackatonkursk.auth


import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.authentication.www.NonceExpiredException
import org.springframework.stereotype.Component
import ru.hackatonkursk.config.SecurityProperties

import javax.servlet.ServletException
import javax.servlet.annotation.WebFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
@WebFilter("/api/auth/token")
class DigestAuthFilter extends DigestAuthenticationFilter {

    DigestAuthFilter(UserDetailsService userDetailsService, SecurityProperties securityProperties) {
        setUserDetailsService(userDetailsService)
        setAuthenticationEntryPoint(digestAuthenticationEntryPoint(securityProperties))
    }

    private DigestAuthenticationEntryPoint digestAuthenticationEntryPoint(
            SecurityProperties securityProperties
    ) {
        def entryPoint = digestAuthenticationEntryPoint()
        entryPoint.setKey(securityProperties.realmKey)
        entryPoint.setRealmName(securityProperties.realmName)
        return entryPoint
    }

    private DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        return new DigestAuthenticationEntryPoint() {
            @Override
            void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
                    throws IOException, ServletException {
                long expiryTime = System.currentTimeMillis() + (nonceValiditySeconds * 1000)
                String signatureValue = (expiryTime + ":" + key).md5()
                String nonceValue = expiryTime + ":" + signatureValue
                String nonceValueBase64 = nonceValue.getBytes().encodeBase64().toString()

                String authenticateHeader = "Digest realm=\"${realmName}\", qop=\"auth\", nonce=\"${nonceValueBase64}\""

                if (authException instanceof NonceExpiredException) {
                    authenticateHeader = "${authenticateHeader}, stale=\"true\""
                }

                response.addHeader("WWW-Authenticate", authenticateHeader)
                response.setStatus(HttpStatus.OK.value())
//        httpResponse.sendError(HttpStatus.UNAUTHORIZED.value(),
//                HttpStatus.UNAUTHORIZED.getReasonPhrase())
            }

        }
    }
}

