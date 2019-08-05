package ru.hackatonkursk.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.SimpleSecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import ru.hackatonkursk.config.SecurityProperties

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.text.ParseException
import java.time.Instant
import java.time.temporal.ChronoUnit

@Service
class JwtService {
    private static final String AUTHORITIES_CLAIM = "auths"

    private static final String BEARER = "Bearer "
    private static final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.HS256
    private static final String SECRET_KEY_ALGORITHM = "HMAC"
    private final Logger logger = LoggerFactory.getLogger(JwtService.class)
    private final SecurityProperties authModuleConfig

    JwtService(SecurityProperties authModuleConfig) {
        this.authModuleConfig = authModuleConfig
    }

    static String getTokenFromHeader(String authHeader) {
        if (authHeader != null) {
            def matchBearerLength = authHeader.length() > BEARER.length()
            if (matchBearerLength) {
                return authHeader.substring(BEARER.length())
            }
        }
        return null
    }

    String getHttpAuthHeaderValue(Authentication authentication) {
        String token = getTokenFromAuthentication(authentication)
        return String.join(" ", "Bearer", token)
    }

    String getTokenFromAuthentication(Authentication authentication) {
        return generateToken(
                authentication.getName(),
                authentication.getAuthorities())
    }

    String generateToken(String subjectName, Collection<? extends GrantedAuthority> authorities) {
        Date expirationTime = Date.from(Instant.now().plus(authModuleConfig.getTokenExpirationMinutes(), ChronoUnit.MINUTES))
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subjectName)
                .issuer(authModuleConfig.getTokenIssuer())
                .expirationTime(expirationTime)
                .claim(AUTHORITIES_CLAIM, authorities.join(','))
                .build()

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWS_ALGORITHM), claimsSet)

        try {
            final SecretKey key = new SecretKeySpec(authModuleConfig.getTokenSecret().getBytes(), SECRET_KEY_ALGORITHM)
            signedJWT.sign(new MACSigner(key))
        } catch (JOSEException e) {
            logger.error("ERROR while signing JWT", e)
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, 'Unable to generate token')
        }

        return signedJWT.serialize()
    }

    JWTClaimsSet verifySignedJWT(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token)
            JWSVerifier verifier = new MACVerifier(authModuleConfig.getTokenSecret())
            boolean valid = signedJWT.verify(verifier)
            if (valid) {
                ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>()
                jwtProcessor.setJWSKeySelector({ header, context ->
                    final SecretKey key = new SecretKeySpec(authModuleConfig.getTokenSecret().getBytes(), SECRET_KEY_ALGORITHM)
                    return List.of(key)
                })
                JWTClaimsSet claimsSet = jwtProcessor.process(signedJWT, null)
                return claimsSet
            } else {
                logger.error("ERROR TOKEN invalid " + token)
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid token")
            }
        } catch (ParseException | JOSEException | BadJOSEException e) {
            logger.error("ERROR while verify JWT: " + token)
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unable to verify token")
        }
    }

    static Authentication getUsernamePasswordAuthenticationToken(JWTClaimsSet claimsSet) {
        String subject = claimsSet.getSubject()
        String auths = (String) claimsSet.getClaim(AUTHORITIES_CLAIM)
        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(auths.split(","))
        return new UsernamePasswordAuthenticationToken(subject, null, authorities)
    }
}
