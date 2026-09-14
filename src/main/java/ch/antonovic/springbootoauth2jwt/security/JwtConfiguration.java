package ch.antonovic.springbootoauth2jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Wires the JOSE infrastructure this application signs and verifies its own tokens with. Because a
 * {@link JwtDecoder} bean is present, Spring Boot's resource server auto-configuration backs off, so no
 * {@code spring.security.oauth2.resourceserver.*} property is needed.
 */
@Configuration
public class JwtConfiguration {

	@Bean
	public SecretKey jwtSigningKey(JwtProperties jwtProperties) {
		return new SecretKeySpec(jwtProperties.secret().getBytes(StandardCharsets.UTF_8),
								 JwtConventions.SECRET_KEY_ALGORITHM);
	}

	@Bean
	public JwtEncoder jwtEncoder(SecretKey jwtSigningKey) {
		return NimbusJwtEncoder.withSecretKey(jwtSigningKey)
				.algorithm(JwtConventions.SIGNATURE_ALGORITHM)
				.build();
	}

	@Bean
	public JwtDecoder jwtDecoder(SecretKey jwtSigningKey, JwtProperties jwtProperties) {
		var jwtDecoder = NimbusJwtDecoder.withSecretKey(jwtSigningKey)
				.macAlgorithm(JwtConventions.SIGNATURE_ALGORITHM)
				.build();
		jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(jwtProperties.issuer()));
		return jwtDecoder;
	}

	/**
	 * Maps the {@code roles} claim back to the {@code ROLE_}-prefixed authorities the rest of Spring Security
	 * expects. Without it, only {@code SCOPE_}-prefixed authorities derived from the {@code scope} claim exist.
	 */
	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		var authoritiesConverter = new JwtGrantedAuthoritiesConverter();
		authoritiesConverter.setAuthoritiesClaimName(JwtConventions.ROLES_CLAIM);
		authoritiesConverter.setAuthorityPrefix(JwtConventions.ROLE_PREFIX);

		var jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
		return jwtAuthenticationConverter;
	}
}
