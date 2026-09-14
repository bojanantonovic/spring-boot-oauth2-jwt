package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Duration;
import java.time.Instant;

/**
 * Builds the real encoder and decoder beans from {@link JwtConfiguration}, so the tests exercise the production wiring
 * instead of a look-alike configuration.
 */
class JwtTestSupport {

	private static final Duration EXPIRED_TOKEN_AGE = Duration.ofHours(2);
	private static final Duration EXPIRED_TOKEN_LIFETIME = Duration.ofHours(1);

	private final JwtConfiguration jwtConfiguration = new JwtConfiguration();

	JwtProperties properties(String secret, String issuer, long expirationMs) {
		return new JwtProperties(secret, issuer, expirationMs);
	}

	JwtEncoder encoder(String secret) {
		return jwtConfiguration.jwtEncoder(jwtConfiguration.jwtSigningKey(properties(secret, null, 0)));
	}

	JwtDecoder decoder(String secret, String issuer) {
		var jwtProperties = properties(secret, issuer, 0);
		return jwtConfiguration.jwtDecoder(jwtConfiguration.jwtSigningKey(jwtProperties), jwtProperties);
	}

	TokenService tokenService(String secret, String issuer, long expirationMs) {
		return new TokenService(encoder(secret), properties(secret, issuer, expirationMs));
	}

	/**
	 * {@link TokenService} cannot issue an expired token, because {@code Jwt} rejects an expiry that is not after
	 * the issuing instant. The encoder is therefore driven directly here.
	 */
	String expiredToken(String secret, String issuer) {
		var issuedAt = Instant.now().minus(EXPIRED_TOKEN_AGE);
		var claims = JwtClaimsSet.builder()
				.issuer(issuer)
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plus(EXPIRED_TOKEN_LIFETIME))
				.subject(TestFixtures.TEST_EMAIL)
				.build();
		var header = JwsHeader.with(JwtConventions.SIGNATURE_ALGORITHM).build();

		return encoder(secret).encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	JwtException decodeFailure(String token, String secret, String issuer) {
		try {
			decoder(secret, issuer).decode(token);
			throw new AssertionError("Expected the token to be rejected, but it was accepted");
		} catch (JwtException exception) {
			return exception;
		}
	}
}
