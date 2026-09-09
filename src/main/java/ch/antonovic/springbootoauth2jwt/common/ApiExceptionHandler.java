package ch.antonovic.springbootoauth2jwt.common;

import ch.antonovic.springbootoauth2jwt.auth.EmailAlreadyInUseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

	private static final String TIMESTAMP_KEY = "timestamp";
	private static final String STATUS_KEY = "status";
	private static final String MESSAGE_KEY = "message";
	private static final String ERRORS_KEY = "errors";
	private static final String INVALID_CREDENTIALS_MESSAGE = "Invalid email or password";
	private static final String VALIDATION_FAILED_MESSAGE = "Validation failed";

	@ExceptionHandler(EmailAlreadyInUseException.class)
	public ResponseEntity<Map<String, Object>> handleEmailAlreadyInUse(EmailAlreadyInUseException exception) {
		return errorResponse(HttpStatus.CONFLICT, exception.getMessage());
	}

	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException exception) {
		return errorResponse(HttpStatus.UNAUTHORIZED, INVALID_CREDENTIALS_MESSAGE);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException exception) {
		Map<String, String> fieldErrors = new LinkedHashMap<>();
		exception.getBindingResult().getFieldErrors()
				.forEach(error -> fieldErrors.put(error.getField(), error.getDefaultMessage()));

		Map<String, Object> body = new LinkedHashMap<>();
		body.put(TIMESTAMP_KEY, Instant.now());
		body.put(STATUS_KEY, HttpStatus.BAD_REQUEST.value());
		body.put(MESSAGE_KEY, VALIDATION_FAILED_MESSAGE);
		body.put(ERRORS_KEY, fieldErrors);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
	}

	private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String message) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put(TIMESTAMP_KEY, Instant.now());
		body.put(STATUS_KEY, status.value());
		body.put(MESSAGE_KEY, message);
		return ResponseEntity.status(status).body(body);
	}
}
