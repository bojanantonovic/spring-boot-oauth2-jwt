package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtConfigTest {

	private static final String HEADER_ALGORITHM_KEY = "alg";
	private static final String TOKEN_VALUE = "irrelevant-for-the-converter";
	private static final long ONE_HOUR_SECONDS = 3600L;

	private final JwtConfig jwtConfig = new JwtConfig();
	private final JwtTestSupport jwtTestSupport = new JwtTestSupport();

	@Test
	void givenTokenSignedWithAnotherSecret_whenDecode_thenTokenIsRejected() {
		// given
		var foreignToken = jwtTestSupport
				.tokenService(TestFixtures.OTHER_SECRET, TestFixtures.TEST_ISSUER, TestFixtures.VALID_EXPIRATION_MS)
				.generateToken(TestFixtures.userDetails(TestFixtures.TEST_EMAIL));

		// when
		var failure = jwtTestSupport.decodeFailure(foreignToken, TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER);

		// then
		assertThat(failure).isNotNull();
	}

	@Test
	void givenTokenOfAnotherIssuer_whenDecode_thenTokenIsRejected() {
		// given
		var foreignToken = jwtTestSupport
				.tokenService(TestFixtures.TEST_SECRET, TestFixtures.OTHER_ISSUER, TestFixtures.VALID_EXPIRATION_MS)
				.generateToken(TestFixtures.userDetails(TestFixtures.TEST_EMAIL));

		// when
		var failure = jwtTestSupport.decodeFailure(foreignToken, TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER);

		// then
		assertThat(failure).isInstanceOf(JwtValidationException.class);
	}

	@Test
	void givenExpiredToken_whenDecode_thenTokenIsRejected() {
		// given
		var expiredToken = jwtTestSupport.expiredToken(TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER);

		// when
		var failure = jwtTestSupport.decodeFailure(expiredToken, TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER);

		// then
		assertThat(failure).isInstanceOf(JwtValidationException.class);
	}

	@Test
	void givenTokenWithRolesClaim_whenConvertingAuthentication_thenRolesBecomePrefixedAuthorities() {
		// given
		var issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		var jwt = Jwt.withTokenValue(TOKEN_VALUE)
				.header(HEADER_ALGORITHM_KEY, JwtConventions.SIGNATURE_ALGORITHM.getName())
				.subject(TestFixtures.TEST_EMAIL)
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plusSeconds(ONE_HOUR_SECONDS))
				.claim(JwtConventions.ROLES_CLAIM, List.of("USER", "ADMIN"))
				.build();

		// when
		var authentication = jwtConfig.jwtAuthenticationConverter().convert(jwt);

		// then
		assertThat(authentication).isNotNull();
		assertThat(authentication.getName()).isEqualTo(TestFixtures.TEST_EMAIL);
		assertThat(authentication.getAuthorities())
				.extracting(GrantedAuthority::getAuthority)
				.containsExactlyInAnyOrder(TestFixtures.USER_AUTHORITY, TestFixtures.ADMIN_AUTHORITY,
										   TestFixtures.BEARER_FACTOR_AUTHORITY);
	}

	@Test
	void givenTokenWithoutRolesClaim_whenConvertingAuthentication_thenThereAreNoRoleAuthorities() {
		// given
		var issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		var jwt = Jwt.withTokenValue(TOKEN_VALUE)
				.header(HEADER_ALGORITHM_KEY, JwtConventions.SIGNATURE_ALGORITHM.getName())
				.claims(claims -> claims.putAll(Map.of(JwtClaimNames.SUB, TestFixtures.TEST_EMAIL)))
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plusSeconds(ONE_HOUR_SECONDS))
				.build();

		// when
		var authentication = jwtConfig.jwtAuthenticationConverter().convert(jwt);

		// then
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorities())
				.extracting(GrantedAuthority::getAuthority)
				.containsExactly(TestFixtures.BEARER_FACTOR_AUTHORITY);
	}
}
