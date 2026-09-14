package ch.antonovic.springbootoauth2jwt.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param secret       shared secret used to sign and verify tokens. Must be at least 256 bits long for {@code HS256}.
 * @param issuer       value of the {@code iss} claim. It is written by the encoder and enforced by the decoder.
 * @param expirationMs lifetime of an issued token in milliseconds.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String secret, String issuer, long expirationMs) {
}
