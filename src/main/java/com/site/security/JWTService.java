package com.site.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

@Service
public class JWTService {

    private final JwtEncoder encoder;
    private final long expirationSeconds;
    private final String issuer;

    public JWTService(@Value("${app.jwt.secret}") String secretB64,
                      @Value("${app.jwt.expiration-seconds:3600}") long expirationSeconds,
                      @Value("${app.jwt.issuer:opsimulator}") String issuer) {

        byte[] key = Base64.getDecoder().decode(secretB64);
        this.encoder = new NimbusJwtEncoder(new ImmutableSecret<SecurityContext>(key));
        this.expirationSeconds = expirationSeconds;
        this.issuer = issuer;
    }

    public String generate(String username, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder b = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(username)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirationSeconds));
        if (extraClaims != null) extraClaims.forEach(b::claim);

        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                b.build()
        )).getTokenValue();
    }

    public long getExpirationSeconds() { return expirationSeconds; }
}
