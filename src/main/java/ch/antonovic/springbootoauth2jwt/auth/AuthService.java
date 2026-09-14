package ch.antonovic.springbootoauth2jwt.auth;

import ch.antonovic.springbootoauth2jwt.auth.dto.AuthResponse;
import ch.antonovic.springbootoauth2jwt.auth.dto.LoginRequest;
import ch.antonovic.springbootoauth2jwt.auth.dto.RegisterRequest;
import ch.antonovic.springbootoauth2jwt.security.TokenService;
import ch.antonovic.springbootoauth2jwt.security.UserDetailsMapper;
import ch.antonovic.springbootoauth2jwt.user.Role;
import ch.antonovic.springbootoauth2jwt.user.User;
import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final TokenService tokenService;

	public AuthResponse register(RegisterRequest request) {
		if (userRepository.existsByEmail(request.email())) {
			throw new EmailAlreadyInUseException(request.email());
		}

		var user = toUser(request);
		userRepository.save(user);

		var userDetails = UserDetailsMapper.toUserDetails(user);
		var token = tokenService.generateToken(userDetails.getUsername(), userDetails.getAuthorities());
		return AuthResponse.of(token, user.getEmail());
	}

	private User toUser(final RegisterRequest request) {
		return User.builder()
				.email(request.email())
				.password(passwordEncoder.encode(request.password()))
				.role(Role.USER)
				.build();
	}

	/**
	 * The returned {@code Authentication} already carries the name and the authorities that the
	 * {@code DaoAuthenticationProvider} loaded to check the password, so the user is not read a second time.
	 */
	public AuthResponse login(LoginRequest request) {
		var authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.email(), request.password()));

		var token = tokenService.generateToken(authentication.getName(), authentication.getAuthorities());
		return AuthResponse.of(token, request.email());
	}
}
