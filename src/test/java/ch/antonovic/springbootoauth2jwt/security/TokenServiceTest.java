package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenServiceTest {

	private final JwtTestSupport jwtTestSupport = new JwtTestSupport();

	@Test
	void givenUserDetails_whenGenerateToken_thenTokenCarriesSubjectIssuerAndExpiry() {
		// given
		var tokenService = tokenService();
		var userDetails = TestFixtures.userDetails(TestFixtures.TEST_EMAIL);

		// when
		var token = tokenService.generateToken(userDetails);

		// then
		var decodedToken = decode(token);
		assertThat(decodedToken.getSubject()).isEqualTo(TestFixtures.TEST_EMAIL);
		assertThat(decodedToken.getIssuer()).hasToString(TestFixtures.TEST_ISSUER);
		assertThat(decodedToken.getIssuedAt()).isNotNull();
		assertThat(decodedToken.getExpiresAt())
				.isEqualTo(decodedToken.getIssuedAt().plusMillis(TestFixtures.VALID_EXPIRATION_MS));
	}

	@Test
	void givenUserDetailsWithRole_whenGenerateToken_thenRolesClaimHoldsRoleWithoutPrefix() {
		// given
		var tokenService = tokenService();
		var userDetails = TestFixtures.userDetails(TestFixtures.TEST_EMAIL, TestFixtures.ADMIN_AUTHORITY);

		// when
		var token = tokenService.generateToken(userDetails);

		// then
		assertThat(decode(token).getClaimAsStringList(JwtConventions.ROLES_CLAIM)).containsExactly("ADMIN");
	}

	@Test
	void givenTokenIssuedWithAnotherSecret_whenDecodedWithTheConfiguredSecret_thenTokenIsRejected() {
		// given
		var foreignTokenService = jwtTestSupport.tokenService(TestFixtures.OTHER_SECRET, TestFixtures.TEST_ISSUER,
															  TestFixtures.VALID_EXPIRATION_MS);
		var foreignToken = foreignTokenService.generateToken(TestFixtures.userDetails(TestFixtures.TEST_EMAIL));

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
