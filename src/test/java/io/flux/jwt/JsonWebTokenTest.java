package io.flux.jwt;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SpringBootTest(properties = "spring.config.location=classpath:application.yaml")
class JsonWebTokenTest {
    private final String jwtSingingKey;
    private final JwtService jwtService;
    public JsonWebTokenTest(@Autowired JwtService jwtService, @Value("${env.JWT_SINGING_KEY}") String jwtSingingKey) {
        this.jwtService = jwtService;
        this.jwtSingingKey = jwtSingingKey;
    }

    @Test
    public void jwtIsEncodedAndDecodedProperly() {
        JsonWebTokenClaims claims = getTestingClaims();
        Map<String, Object> decodedClaims = claims.parseAsMap();
        assertEquals(3, decodedClaims.size());
        assertTrue(decodedClaims.containsKey("username"));
        assertEquals("ChocolateMagnateUA", decodedClaims.get("username"));
        assertTrue(decodedClaims.containsKey("accountAgeDays"));
        assertEquals(25, decodedClaims.get("accountAgeDays"));
        assertTrue(decodedClaims.containsKey("premium"));
        assertEquals(true, decodedClaims.get("premium"));
    }

    @Test
    public void testGenerateJwtToken() {
        JsonWebTokenClaims claims = getTestingClaims();
        String token = this.jwtService.generateJwtTokenString(claims);
        assertTrue(this.jwtService.isValidJwtToken(token));
    }

    @Test
    public void shouldRejectImproperlySignedToken() {
        String tamperedSingingKey = this.jwtSingingKey + "gj2u1i12y1ob12o1";
        JsonWebToken jwt = new JsonWebToken(getTestingClaims(), tamperedSingingKey);
        assertFalse(jwt.verify(this.jwtSingingKey));
    }

    @Contract(" -> new")
    public static @NotNull JsonWebTokenClaims getTestingClaims() {
        HashMap<String, Object> claims = new HashMap<>(3);
        claims.put("username", "ChocolateMagnateUA");
        claims.put("accountAgeDays", 25);
        claims.put("premium", true);
        return new JsonWebTokenClaims(claims);
    }

}