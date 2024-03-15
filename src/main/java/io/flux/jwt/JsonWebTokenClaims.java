package io.flux.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public class JsonWebTokenClaims {
    private final JWTClaimsSet claims;

    public JsonWebTokenClaims(@NotNull Map<String, Object> map) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        map.forEach(builder::claim);
        this.claims = builder.build();
    }

    public Map<String, Object> parseAsMap() {
        return this.claims.toJSONObject(false);
    }

    public String getJwtId() {
        return this.claims.getJWTID();
    }

    public String getIssuer() {
        return this.claims.getIssuer();
    }

    public String getSubject() {
        return this.claims.getSubject();
    }

    public List<String> getAudience() {
        return this.claims.getAudience();
    }

    public Instant getExpirationTime() {
        return this.claims.getExpirationTime().toInstant();
    }

    public Instant getNotBeforeTime() {
        return this.claims.getNotBeforeTime().toInstant();
    }

    public Instant getIssuedAtTime() {
        return this.claims.getIssueTime().toInstant();
    }
}
