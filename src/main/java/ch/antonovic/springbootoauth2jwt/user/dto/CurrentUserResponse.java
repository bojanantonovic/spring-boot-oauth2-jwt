package ch.antonovic.springbootoauth2jwt.user.dto;

import java.util.List;

public record CurrentUserResponse(
		String email,
		List<String> authorities
) {
}
