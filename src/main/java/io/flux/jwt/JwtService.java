package io.flux.jwt;

import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;

@Service
public class JwtService {
    private final String jwtSingingKey;

    public JwtService(@Value("${env.JWT_SINGING_KEY}") String jwtSingingKey) {
        this.jwtSingingKey = jwtSingingKey;
    }

    public String generateJwtTokenString(JsonWebTokenClaims claims) {
        return new JsonWebToken(claims, this.jwtSingingKey).toString();
    }

    public JsonWebToken parseAuthorizationHeader(@NotNull String authorization) throws IllegalArgumentException, ParseException {
        String authorizationMethodSlice = authorization.substring(0, 7);
        if (!authorization.startsWith("Bearer ")) throw new IllegalArgumentException(
                "JWT must begin with \"Bearer \", instead " + authorizationMethodSlice + " was given.");

        String token = authorization.substring(7);
        return new JsonWebToken(token);
    }

    public boolean isTokenExpired(@NotNull JsonWebToken token) {
        try {
            Instant expiration = token.getClaims().getExpirationTime();
            return Instant.now().isAfter(expiration);
        } catch (ParseException e) {
            // Since this method is primarily used to tell if the token is valid and relevant,
            // If token is invalid, we implicitly treat it as invalid or expired.
            return false;
        }
    }

    public boolean isValidJwtToken(@NotNull String token) {
        try {
            if (token.startsWith("Bearer ")) token = token.substring(7);
            JsonWebToken jwt = new JsonWebToken(token);
            return jwt.verify(this.jwtSingingKey);
        } catch (ParseException e) { return false; }
    }
}
