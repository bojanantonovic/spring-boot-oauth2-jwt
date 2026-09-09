package ch.antonovic.springbootoauth2jwt.auth.dto;

public record AuthResponse(
		String token,
		String tokenType,
		String email
) {

	private static final String BEARER_TOKEN_TYPE = "Bearer";

	public static AuthResponse of(String token, String email) {
		return new AuthResponse(token, BEARER_TOKEN_TYPE, email);
	}
}
