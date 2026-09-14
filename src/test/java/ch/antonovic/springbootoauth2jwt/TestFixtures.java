package ch.antonovic.springbootoauth2jwt;

import ch.antonovic.springbootoauth2jwt.user.Role;
import ch.antonovic.springbootoauth2jwt.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

public final class TestFixtures {

	public static final String TEST_EMAIL = "jane.doe@example.com";
	public static final String OTHER_EMAIL = "other.user@example.com";
	public static final String UNKNOWN_EMAIL = "unknown@example.com";
	public static final String TEST_PASSWORD = "s3curePassword!";
	public static final String ENCODED_PASSWORD = "encoded-password";
	public static final String TEST_ISSUER = "http://localhost:8080";
	public static final String OTHER_ISSUER = "http://localhost:9999";
	public static final String TEST_SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A713474";
	public static final String OTHER_SECRET = "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B";
	public static final long VALID_EXPIRATION_MS = 3600000L;
	public static final String USER_AUTHORITY = "ROLE_USER";
	public static final String ADMIN_AUTHORITY = "ROLE_ADMIN";
	/**
	 * Authority Spring Security 7 adds for every request authenticated by a bearer token.
	 */
	public static final String BEARER_FACTOR_AUTHORITY = "FACTOR_BEARER";

	public static List<GrantedAuthority> authorities(String authority) {
		return List.of(new SimpleGrantedAuthority(authority));
	}

	public static User user(String email, Role role) {
		return User.builder()
				.email(email)
				.password(ENCODED_PASSWORD)
				.role(role)
				.build();
	}

	private TestFixtures() {
	}
}
