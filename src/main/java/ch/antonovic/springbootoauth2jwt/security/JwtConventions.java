package ch.antonovic.springbootoauth2jwt.security;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

/**
 * The conventions that the token encoder and the token decoder have to agree on.
 */
final class JwtConventions {

	static final MacAlgorithm SIGNATURE_ALGORITHM = MacAlgorithm.HS256;

	/**
	 * Java name of {@link #SIGNATURE_ALGORITHM}, needed to turn the configured secret into a {@code SecretKey}.
	 */
	static final String SECRET_KEY_ALGORITHM = "HmacSHA256";

	/**
	 * Custom claim holding the roles of the subject, without the {@link #ROLE_PREFIX}.
	 */
	static final String ROLES_CLAIM = "roles";

	static final String ROLE_PREFIX = "ROLE_";

	private JwtConventions() {
	}
}
