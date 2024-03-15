package io.flux.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import static io.flux.jwt.JsonWebTokenTest.getTestingClaims;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SpringBootTest(properties = "spring.config.location=classpath:application.yaml")
class JwtServiceTest {
    private final String jwtSingingKey;
    private final JwtService jwtService;
    private static final String token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.QHiBOr1uDyre3A3-9M4r8wJw8TvS-bNFidCVGUMKiA4";

    public JwtServiceTest(@Autowired JwtService jwtService, @Value("${env.JWT_SINGING_KEY}") String jwtSingingKey) {
        this.jwtService = jwtService;
        this.jwtSingingKey = jwtSingingKey;
    }

    @Test
    public void testGeneratedTokenIsSigned() {
        JsonWebToken jwt = new JsonWebToken(getTestingClaims(), this.jwtSingingKey);
        assertDoesNotThrow(() -> assertTrue(jwt.verify(this.jwtSingingKey)));
    }

    @Test
    public void generateJwtTokenString() throws ParseException {
        JsonWebTokenClaims claims = getTestingClaims();
        JsonWebToken jwt = new JsonWebToken(claims, jwtSingingKey);
        String token = jwt.toString();
        JsonWebToken reversedJwt = new JsonWebToken(token);
        assertEquals(jwt.toString(), reversedJwt.toString());
    }

    @Test
    public void shouldRejectInvalidJwtHeader() {
        String token = "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertThrows(IllegalArgumentException.class, () -> this.jwtService.parseAuthorizationHeader(token));
    }

    @Test
    public void testParseAuthorizationHeader() {
        assertDoesNotThrow(() -> {
            JsonWebToken jwt = this.jwtService.parseAuthorizationHeader(token);
            assertTrue(jwt.verify(this.jwtSingingKey));
        });
    }

    @Test
    public void testIsTokenExpired() {
        Map<String, Object> claims = getTestingClaims().parseAsMap();
        claims.put("exp", Instant.now().getEpochSecond() + 10000);
        JsonWebToken jwt = new JsonWebToken(new JsonWebTokenClaims(claims), this.jwtSingingKey);
        assertFalse(this.jwtService.isTokenExpired(jwt));

        claims.put("exp", Instant.now().getEpochSecond() - 400);
        jwt = new JsonWebToken(new JsonWebTokenClaims(claims), this.jwtSingingKey);
        assertTrue(this.jwtService.isTokenExpired(jwt));
    }

    @Test
    public void isValidJwtToken() throws ParseException {
        assertTrue(this.jwtService.isValidJwtToken(token));
        String invalidToken = token + ".28198hnm,.";
        assertFalse(this.jwtService.isValidJwtToken(invalidToken));
    }
}