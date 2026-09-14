package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.user.User;
import lombok.experimental.UtilityClass;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * The single place where a {@link User} becomes a {@link UserDetails}, so that a token issued right after
 * registration cannot end up carrying different claims than one issued after a login.
 */
@UtilityClass
public final class UserDetailsMapper {

	public UserDetails toUserDetails(User user) {
		return org.springframework.security.core.userdetails.User
				.withUsername(user.getEmail())
				.password(user.getPassword())
				.authorities(JwtConventions.ROLE_PREFIX + user.getRole().name())
				.build();
	}

}
