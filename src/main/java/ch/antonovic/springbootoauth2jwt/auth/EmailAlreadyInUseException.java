package ch.antonovic.springbootoauth2jwt.auth;

public class EmailAlreadyInUseException extends RuntimeException {

	public EmailAlreadyInUseException(String email) {
		super("Email already in use: " + email);
	}
}
