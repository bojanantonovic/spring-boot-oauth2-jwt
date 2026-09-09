package ch.antonovic.springbootoauth2jwt.auth;

import ch.antonovic.springbootoauth2jwt.auth.dto.AuthResponse;
import ch.antonovic.springbootoauth2jwt.auth.dto.LoginRequest;
import ch.antonovic.springbootoauth2jwt.auth.dto.RegisterRequest;
import ch.antonovic.springbootoauth2jwt.security.TokenService;
import ch.antonovic.springbootoauth2jwt.user.Role;
import ch.antonovic.springbootoauth2jwt.user.User;
import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final TokenService tokenService;
	private final UserDetailsService userDetailsService;

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

		var userDetails = userDetailsService.loadUserByUsername(user.getEmail());
		var token = tokenService.generateToken(userDetails);
		return AuthResponse.of(token, user.getEmail());
	}

	public AuthResponse login(LoginRequest request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.email(), request.password()));

		var userDetails = userDetailsService.loadUserByUsername(request.email());
		var token = tokenService.generateToken(userDetails);
		return AuthResponse.of(token, request.email());
	}
}
