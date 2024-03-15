package io.flux.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class JsonWebToken {
    private final SignedJWT jwt;

    public JsonWebToken(String token) throws ParseException {
        //We don't need to sign the JWT token because SignedJWT constructor already signs it.
        this.jwt = SignedJWT.parse(token);
    }

    public JsonWebToken(JsonWebTokenClaims claims, @NotNull String jwtSingingKey) {
        JWSHeader header = getDefaultHeader();
        JWTClaimsSet claimSet = parseJwtClaims(claims);
        this.jwt = new SignedJWT(header, claimSet);
        if (!jwtSingingKey.isBlank()) signJwtToken(jwtSingingKey);
    }

    private void signJwtToken(String jwtSingingKey) {
        try {
            JWSSigner signer = new MACSigner(jwtSingingKey);
            this.jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("[JsonWebToken] failed to sing the JWT token with " + jwtSingingKey + ".\n" + e.getMessage());
        }
    }

    @Contract(" -> new")
    private @NotNull JWSHeader getDefaultHeader() {
        return new JWSHeader(JWSAlgorithm.HS384); //HS512 is not supported at the moment.
    }

    private JWTClaimsSet parseJwtClaims(@NotNull JsonWebTokenClaims claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        Map<String, Object> parsedClaims = claims.parseAsMap();
        parsedClaims.forEach(builder::claim);
        return builder.build();
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        JsonWebToken other = (JsonWebToken) object;
        return Objects.equals(this.toString(), other.toString());
    }

    public String toString() {
        return this.jwt.serialize();
    }

    public JsonWebTokenHeader getHeader() {
        return new JsonWebTokenHeader(this.jwt.getHeader());
    }

    public JsonWebTokenClaims getClaims() throws ParseException {
        return new JsonWebTokenClaims(this.jwt.getJWTClaimsSet());
    }

    public boolean verify(String jwtSingingKey) {
        try {
            JWSVerifier verifier = new MACVerifier(jwtSingingKey);
            return jwt.verify(verifier);
        } catch (JOSEException e) {
            return false;
        }
    }

}
