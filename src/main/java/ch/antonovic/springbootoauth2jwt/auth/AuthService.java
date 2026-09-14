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
import org.springframework.security.core.userdetails.UserDetails;
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

		var user = User.builder()
				.email(request.email())
				.password(passwordEncoder.encode(request.password()))
				.role(Role.USER)
				.build();
		userRepository.save(user);

		var token = tokenService.generateToken(UserDetailsMapper.toUserDetails(user));
		return AuthResponse.of(token, user.getEmail());
	}

	/**
	 * The principal of the returned {@code Authentication} is the {@link UserDetails} that the
	 * {@code DaoAuthenticationProvider} already loaded to check the password, so the user is not read twice.
	 */
	public AuthResponse login(LoginRequest request) {
		var authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.email(), request.password()));

		var token = tokenService.generateToken((UserDetails) authentication.getPrincipal());
		return AuthResponse.of(token, request.email());
	}
}
