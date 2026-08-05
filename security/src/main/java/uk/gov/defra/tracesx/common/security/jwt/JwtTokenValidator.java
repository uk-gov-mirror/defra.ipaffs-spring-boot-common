package uk.gov.defra.tracesx.common.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import uk.gov.defra.tracesx.common.exceptions.JwtAuthenticationException;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.KeyAndClaims;

@Component
public class JwtTokenValidator {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenValidator.class);

  private final JwtUserMapper jwtUserMapper;
  private final JwksCache jwksCache;

  private enum VerificationResult {
    SUCCESS,
    INVALID_ISSUER,
    INVALID_AUDIENCE,
    EXPIRED,
    GENERAL_ERROR
  }

  public JwtTokenValidator(JwtUserMapper jwtUserMapper, JwksCache jwksCache) {
    this.jwtUserMapper = jwtUserMapper;
    this.jwksCache = jwksCache;
  }

  public IdTokenUserDetails validateToken(String idToken) {
    Map<String, Object> decoded = decode(idToken);
    return jwtUserMapper.createUser(decoded, idToken);
  }

  private Map<String, Object> decode(String idToken) {
    try {
      SignedJWT jwt = SignedJWT.parse(idToken);
      String kid = getKeyId(jwt);

      for (KeyAndClaims keyAndClaim : jwksCache.getPublicKeys(kid)) {
        if (verifySignature(jwt, keyAndClaim.getKey())) {
          JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
          VerificationResult result = verifyClaims(claimsSet, keyAndClaim);

          if (result == VerificationResult.SUCCESS) {
            return claimsSet.getClaims();
          } else {
            LOGGER.error("JWT verification failed: {}", result);
          }
        } else {
          LOGGER.error("Could not verify signature of JWT.");
        }
      }
    } catch (ParseException exception) {
      LOGGER.error("Failed to parse JWT token.", exception);
    }

    throw unauthorizedException();
  }

  private String getKeyId(SignedJWT jwt) {
    String kid = jwt.getHeader().getKeyID();
    if (StringUtils.isEmpty(kid)) {
      LOGGER.error("Key id (kid) is missing from the id token header.");
      throw unauthorizedException();
    }
    return kid;
  }

  private boolean verifySignature(SignedJWT jwt, Key key) {
    JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) key);
    try {
      return jwt.verify(verifier);
    } catch (JOSEException exception) {
      LOGGER.error("Error verifying signature of JWT.", exception);
      return false;
    }
  }

  private VerificationResult verifyClaims(JWTClaimsSet claims, KeyAndClaims keyAndClaims) {
    try {
      new DefaultJWTClaimsVerifier<>(
          new JWTClaimsSet.Builder()
              .issuer(keyAndClaims.getIss())
              .audience(keyAndClaims.getAud())
              .build(),
          Set.of("exp"))
          .verify(claims, null);

      return VerificationResult.SUCCESS;
    } catch (BadJWTException exception) {
      if (exception.getMessage().contains("issuer")) {
        LOGGER.error("Invalid issuer claim in JWT.", exception);
        return VerificationResult.INVALID_ISSUER;
      } else if (exception.getMessage().contains("audience")) {
        LOGGER.error("Invalid audience claim in JWT.", exception);
        return VerificationResult.INVALID_AUDIENCE;
      } else if (exception.getMessage().contains("exp")) {
        LOGGER.error("JWT has expired.", exception);
        return VerificationResult.EXPIRED;
      } else {
        LOGGER.error("JWT verification failed due to unknown error.", exception);
        return VerificationResult.GENERAL_ERROR;
      }
    }
  }

  private JwtAuthenticationException unauthorizedException() {
    return new JwtAuthenticationException("Unable to validate credentials.");
  }
}
