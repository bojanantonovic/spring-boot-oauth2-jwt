package ch.antonovic.springbootoauth2jwt.auth;

import ch.antonovic.springbootoauth2jwt.auth.dto.AuthResponse;
import ch.antonovic.springbootoauth2jwt.auth.dto.LoginRequest;
import ch.antonovic.springbootoauth2jwt.auth.dto.RegisterRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(AuthController.BASE_PATH)
@RequiredArgsConstructor
public class AuthController {

	static final String BASE_PATH = "/api/auth";
	private static final String REGISTER_PATH = "/register";
	private static final String LOGIN_PATH = "/login";

	private final AuthService authService;

	@PostMapping(REGISTER_PATH)
	public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
	}

	@PostMapping(LOGIN_PATH)
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
		return ResponseEntity.ok(authService.login(request));
	}
}
