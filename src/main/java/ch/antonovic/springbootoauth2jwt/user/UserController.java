package ch.antonovic.springbootoauth2jwt.user;

import ch.antonovic.springbootoauth2jwt.user.dto.CurrentUserResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(UserController.BASE_PATH)
public class UserController {

	static final String BASE_PATH = "/api/users";
	private static final String ME_PATH = "/me";

	/**
	 * The principal is the decoded token itself: the resource server verified it before this method is reached,
	 * so no database lookup is needed to answer the request.
	 */
	@GetMapping(ME_PATH)
	public CurrentUserResponse me(@AuthenticationPrincipal Jwt jwt, Authentication authentication) {
		var authorities = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.toList();

		return new CurrentUserResponse(jwt.getSubject(), authorities);
	}
}
