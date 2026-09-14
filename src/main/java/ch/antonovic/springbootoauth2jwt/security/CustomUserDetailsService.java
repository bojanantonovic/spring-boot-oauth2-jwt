package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Used while issuing a token, that is on {@code /api/auth/**} only. Requests carrying a bearer token are
 * authenticated from the token itself and never reach this service.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private static final String USER_NOT_FOUND_MESSAGE = "No user found with email: ";

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(@NonNull String email) throws UsernameNotFoundException {
		var user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException(USER_NOT_FOUND_MESSAGE + email));

		return UserDetailsMapper.toUserDetails(user);
	}
}
