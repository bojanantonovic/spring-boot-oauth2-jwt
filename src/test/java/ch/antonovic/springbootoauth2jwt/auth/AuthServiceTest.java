package ch.antonovic.springbootoauth2jwt.auth;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import ch.antonovic.springbootoauth2jwt.auth.dto.LoginRequest;
import ch.antonovic.springbootoauth2jwt.auth.dto.RegisterRequest;
import ch.antonovic.springbootoauth2jwt.security.TokenService;
import ch.antonovic.springbootoauth2jwt.user.Role;
import ch.antonovic.springbootoauth2jwt.user.User;
import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

	private static final String GENERATED_TOKEN = "generated-token";

	@Mock
	private UserRepository userRepository;

	@Mock
	private PasswordEncoder passwordEncoder;

	@Mock
	private AuthenticationManager authenticationManager;

	@Mock
	private TokenService tokenService;

	@InjectMocks
	private AuthService authService;

	@Test
	void givenNewEmail_whenRegister_thenSavesUserAndReturnsToken() {
		// given
		var request = new RegisterRequest(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD);
		when(userRepository.existsByEmail(TestFixtures.TEST_EMAIL)).thenReturn(false);
		when(passwordEncoder.encode(TestFixtures.TEST_PASSWORD)).thenReturn(TestFixtures.ENCODED_PASSWORD);
		when(tokenService.generateToken(any(), any())).thenReturn(GENERATED_TOKEN);

		// when
		var response = authService.register(request);

		// then
		assertThat(response.token()).isEqualTo(GENERATED_TOKEN);
		assertThat(response.email()).isEqualTo(TestFixtures.TEST_EMAIL);

		var savedUserCaptor = ArgumentCaptor.forClass(User.class);
		verify(userRepository).save(savedUserCaptor.capture());
		var savedUser = savedUserCaptor.getValue();
		assertThat(savedUser.getEmail()).isEqualTo(TestFixtures.TEST_EMAIL);
		assertThat(savedUser.getPassword()).isEqualTo(TestFixtures.ENCODED_PASSWORD);
		assertThat(savedUser.getRole()).isEqualTo(Role.USER);

		ArgumentCaptor<Collection<? extends GrantedAuthority>> authoritiesCaptor = ArgumentCaptor.captor();
		verify(tokenService).generateToken(eq(TestFixtures.TEST_EMAIL), authoritiesCaptor.capture());
		assertThat(authoritiesCaptor.getValue()).extracting(GrantedAuthority::getAuthority)
				.containsExactly(TestFixtures.USER_AUTHORITY);
	}

	@Test
	void givenEmailAlreadyInUse_whenRegister_thenThrowsEmailAlreadyInUseException() {
		// given
		var request = new RegisterRequest(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD);
		when(userRepository.existsByEmail(TestFixtures.TEST_EMAIL)).thenReturn(true);

		// when / then
		assertThatThrownBy(() -> authService.register(request))
				.isInstanceOf(EmailAlreadyInUseException.class)
				.hasMessageContaining(TestFixtures.TEST_EMAIL);
		verify(userRepository, never()).save(any());
		verifyNoInteractions(passwordEncoder, tokenService);
	}

	@Test
	void givenValidCredentials_whenLogin_thenReturnsToken() {
		// given
		var request = new LoginRequest(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD);
		var authorities = TestFixtures.authorities(TestFixtures.USER_AUTHORITY);
		when(authenticationManager.authenticate(any())).thenReturn(UsernamePasswordAuthenticationToken
																		   .authenticated(TestFixtures.TEST_EMAIL, null, authorities));
		when(tokenService.generateToken(TestFixtures.TEST_EMAIL, authorities)).thenReturn(GENERATED_TOKEN);

		// when
		var response = authService.login(request);

		// then
		assertThat(response.token()).isEqualTo(GENERATED_TOKEN);
		assertThat(response.email()).isEqualTo(TestFixtures.TEST_EMAIL);
		verify(authenticationManager).authenticate(
				eq(new UsernamePasswordAuthenticationToken(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD)));
	}

	@Test
	void givenInvalidCredentials_whenLogin_thenPropagatesAuthenticationExceptionWithoutIssuingToken() {
		// given
		var request = new LoginRequest(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD);
		when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

		// when / then
		assertThatThrownBy(() -> authService.login(request)).isInstanceOf(BadCredentialsException.class);
		verifyNoInteractions(tokenService);
	}
}
