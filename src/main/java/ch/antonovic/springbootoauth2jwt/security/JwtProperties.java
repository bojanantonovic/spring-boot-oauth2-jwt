package ch.antonovic.springbootoauth2jwt.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
@Getter
@Setter
public class JwtProperties {

	/**
	 * Shared secret used to sign and verify tokens. Must be at least 256 bits long for {@code HS256}.
	 */
	private String secret;

	/**
	 * Value of the {@code iss} claim. It is written by the encoder and enforced by the decoder.
	 */
	private String issuer;

	private long expirationMs;
}
