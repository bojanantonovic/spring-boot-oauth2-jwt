package ch.antonovic.springbootoauth2jwt.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(

		@NotBlank
		@Email
		String email,

		@NotBlank
		@Size(min = RegisterRequest.MIN_PASSWORD_LENGTH, message = "Password must be at least 8 characters long")
		String password
) {
	static final int MIN_PASSWORD_LENGTH = 8;
}
