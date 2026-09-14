package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenServiceTest {

	private final JwtTestSupport jwtTestSupport = new JwtTestSupport();

	@Test
	void whenGenerateToken_thenTokenCarriesSubjectIssuerAndExpiry() {
		// given
		var tokenService = tokenService();

		// when
		var token = tokenService.generateToken(TestFixtures.TEST_EMAIL,
											   TestFixtures.authorities(TestFixtures.USER_AUTHORITY));

		// then
		var decodedToken = decode(token);
		assertThat(decodedToken.getSubject()).isEqualTo(TestFixtures.TEST_EMAIL);
		assertThat(decodedToken.getIssuer()).hasToString(TestFixtures.TEST_ISSUER);
		assertThat(decodedToken.getIssuedAt()).isNotNull();
		assertThat(decodedToken.getExpiresAt())
				.isEqualTo(decodedToken.getIssuedAt().plusMillis(TestFixtures.VALID_EXPIRATION_MS));
	}

	@Test
	void givenPrefixedAuthority_whenGenerateToken_thenRolesClaimHoldsRoleWithoutPrefix() {
		// given
		var tokenService = tokenService();

		// when
		var token = tokenService.generateToken(TestFixtures.TEST_EMAIL,
											   TestFixtures.authorities(TestFixtures.ADMIN_AUTHORITY));

		// then
		assertThat(decode(token).getClaimAsStringList(JwtConventions.ROLES_CLAIM)).containsExactly("ADMIN");
	}

	@Test
	void givenTokenIssuedWithAnotherSecret_whenDecodedWithTheConfiguredSecret_thenTokenIsRejected() {
		// given
		var foreignTokenService = jwtTestSupport.tokenService(TestFixtures.OTHER_SECRET, TestFixtures.TEST_ISSUER,
															  TestFixtures.VALID_EXPIRATION_MS);
		var foreignToken = foreignTokenService.generateToken(TestFixtures.TEST_EMAIL,
															 TestFixtures.authorities(TestFixtures.USER_AUTHORITY));

		// when
		var failure = jwtTestSupport.decodeFailure(foreignToken, TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER);

		// then
		assertThat(failure).isNotNull();
	}

	private TokenService tokenService() {
		return jwtTestSupport.tokenService(TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER,
										   TestFixtures.VALID_EXPIRATION_MS);
	}

	private org.springframework.security.oauth2.jwt.Jwt decode(String token) {
		return jwtTestSupport.decoder(TestFixtures.TEST_SECRET, TestFixtures.TEST_ISSUER).decode(token);
	}
}
