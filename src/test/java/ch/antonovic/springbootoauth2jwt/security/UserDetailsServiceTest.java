package ch.antonovic.springbootoauth2jwt.security;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import ch.antonovic.springbootoauth2jwt.user.Role;
import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceTest {

	private final SecurityConfiguration securityConfiguration = new SecurityConfiguration();

	@Mock
	private UserRepository userRepository;

	@Test
	void givenExistingUser_whenLoadUserByUsername_thenReturnsUserDetailsWithPasswordAndRole() {
		// given
		var user = TestFixtures.user(TestFixtures.TEST_EMAIL, Role.ADMIN);
		when(userRepository.findByEmail(TestFixtures.TEST_EMAIL)).thenReturn(Optional.of(user));

		// when
		var userDetails = securityConfiguration.userDetailsService(userRepository)
				.loadUserByUsername(TestFixtures.TEST_EMAIL);

		// then
		assertThat(userDetails.getUsername()).isEqualTo(TestFixtures.TEST_EMAIL);
		assertThat(userDetails.getPassword()).isEqualTo(TestFixtures.ENCODED_PASSWORD);
		assertThat(userDetails.getAuthorities())
				.extracting(GrantedAuthority::getAuthority)
				.containsExactly(TestFixtures.ADMIN_AUTHORITY);
	}

	@Test
	void givenUnknownEmail_whenLoadUserByUsername_thenThrowsUsernameNotFoundException() {
		// given
		when(userRepository.findByEmail(TestFixtures.UNKNOWN_EMAIL)).thenReturn(Optional.empty());
		var userDetailsService = securityConfiguration.userDetailsService(userRepository);

		// when / then
		assertThatThrownBy(() -> userDetailsService.loadUserByUsername(TestFixtures.UNKNOWN_EMAIL))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessageContaining(TestFixtures.UNKNOWN_EMAIL);
	}
}
