package ru.hackatonkursk.config

import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.NonceExpiredException

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class BrowserDigestAuthenticationEntryPoint extends DigestAuthenticationEntryPoint {

    /**
     * I overrode this method because I did not found any ways for modification of
     * response header `WWW-Authenticate`
     * @param request
     * @param response
     * @param authException
     * @throws IOException* @throws javax.servlet.ServletException
     */
    @Override
    void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response

        // compute a nonce (do not use remote IP address due to proxy farms)
        // format of nonce is:
        // base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
        long expiryTime = System.currentTimeMillis() + (nonceValiditySeconds * 1000)
        String signatureValue = (expiryTime + ":" + key).md5()
        String nonceValue = expiryTime + ":" + signatureValue
        String nonceValueBase64 = nonceValue.getBytes().encodeBase64().toString()

        // qop is quality of protection, as defined by RFC 2617.
        // we do not use opaque due to IE violation of RFC 2617 in not
        // representing opaque on subsequent requests in same session.
        String authenticateHeader = "X-Digest realm=\"${realmName}\", qop=\"auth\", nonce=\"${nonceValueBase64}\""

        if (authException instanceof NonceExpiredException) {
            authenticateHeader = "${authenticateHeader}, stale=\"true\""
        }

        httpResponse.addHeader("WWW-Authenticate", authenticateHeader)
        httpResponse.sendError(HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase())
    }

}
