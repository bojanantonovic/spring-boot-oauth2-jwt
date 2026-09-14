package ch.antonovic.springbootoauth2jwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Issues the access tokens returned by the authentication endpoints. Verification is not implemented here: it is
 * done by the resource server's {@code JwtDecoder} before a request reaches any controller.
 */
@Service
@RequiredArgsConstructor
public class TokenService {

	private final JwtEncoder jwtEncoder;
	private final JwtProperties jwtProperties;

	public String generateToken(String subject, Collection<? extends GrantedAuthority> authorities) {
		var issuedAt = Instant.now();
		var claims = JwtClaimsSet.builder()
				.issuer(jwtProperties.issuer())
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plusMillis(jwtProperties.expirationMs()))
				.subject(subject)
				.claim(JwtConventions.ROLES_CLAIM, rolesOf(authorities))
				.build();
		var header = JwsHeader.with(JwtConventions.SIGNATURE_ALGORITHM).build();

		return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	private static List<String> rolesOf(Collection<? extends GrantedAuthority> authorities) {
		return authorities.stream()
				.map(GrantedAuthority::getAuthority)
				.filter(Objects::nonNull)
				.filter(authority -> authority.startsWith(JwtConventions.ROLE_PREFIX))
				.map(authority -> authority.substring(JwtConventions.ROLE_PREFIX.length()))
				.toList();
	}
}
