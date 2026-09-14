package ch.antonovic.springbootoauth2jwt.auth;

import ch.antonovic.springbootoauth2jwt.TestFixtures;
import ch.antonovic.springbootoauth2jwt.auth.dto.LoginRequest;
import ch.antonovic.springbootoauth2jwt.auth.dto.RegisterRequest;
import ch.antonovic.springbootoauth2jwt.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

	private static final String REGISTER_URL = "/api/auth/register";
	private static final String LOGIN_URL = "/api/auth/login";
	private static final String ME_URL = "/api/users/me";
	private static final String WRONG_PASSWORD = "wrongPassword!";
	private static final String MALFORMED_EMAIL = "not-an-email";
	private static final String TOO_SHORT_PASSWORD = "short1";
	private static final String VALIDATION_FAILED_MESSAGE = "Validation failed";
	private static final String MUST_BE_WELL_FORMED_EMAIL_MESSAGE = "must be a well-formed email address";
	private static final String MUST_NOT_BE_BLANK_MESSAGE = "must not be blank";
	private static final String PASSWORD_TOO_SHORT_MESSAGE = "Password must be at least 8 characters long";
	private static final String BEARER_PREFIX = "Bearer ";
	private static final String BEARER_CHALLENGE = "Bearer";
	private static final String INVALID_TOKEN_ERROR = "invalid_token";
	private static final String MALFORMED_TOKEN = "not-a-jwt";
	private static final String SIGNATURE_TAMPER_SUFFIX = "tampered";
	private static final String TOKEN_FIELD = "token";

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@BeforeEach
	void cleanDatabase() {
		userRepository.deleteAll();
	}

	@Test
	void givenNewEmail_whenRegister_thenReturnsCreatedWithToken() throws Exception {
		// given
		var requestBody = registerBody(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD);

		// when
		var result = mockMvc.perform(post(REGISTER_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(requestBody));

		// then
		result.andExpect(status().isCreated())
				.andExpect(jsonPath("$.token").value(notNullValue()))
				.andExpect(jsonPath("$.email").value(TestFixtures.TEST_EMAIL));
	}

	@Test
	void givenAlreadyRegisteredEmail_whenRegisterAgain_thenReturnsConflict() throws Exception {
		// given
		registerAndReturnToken();

		// when
		var result = mockMvc.perform(post(REGISTER_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(registerBody(TestFixtures.TEST_EMAIL,
																   TestFixtures.TEST_PASSWORD)));

		// then
		result.andExpect(status().isConflict());
	}

	@Test
	void givenRegisteredUser_whenLoginWithCorrectPassword_thenReturnsToken() throws Exception {
		// given
		registerAndReturnToken();
		var loginBody = objectMapper.writeValueAsString(
				new LoginRequest(TestFixtures.TEST_EMAIL, TestFixtures.TEST_PASSWORD));

		// when
		var result = mockMvc.perform(post(LOGIN_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(loginBody));

		// then
		result.andExpect(status().isOk())
				.andExpect(jsonPath("$.token").value(notNullValue()));
	}

	@Test
	void givenRegisteredUser_whenLoginWithWrongPassword_thenReturnsUnauthorized() throws Exception {
		// given
		registerAndReturnToken();
		var loginBody = objectMapper.writeValueAsString(new LoginRequest(TestFixtures.TEST_EMAIL, WRONG_PASSWORD));

		// when
		var result = mockMvc.perform(post(LOGIN_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(loginBody));

		// then
		result.andExpect(status().isUnauthorized());
	}

	@Test
	void givenMalformedEmail_whenRegister_thenReturnsBadRequestWithFieldError() throws Exception {
		// given
		var requestBody = registerBody(MALFORMED_EMAIL, TestFixtures.TEST_PASSWORD);

		// when
		var result = mockMvc.perform(post(REGISTER_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(requestBody));

		// then
		result.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.message").value(VALIDATION_FAILED_MESSAGE))
				.andExpect(jsonPath("$.errors.email").value(MUST_BE_WELL_FORMED_EMAIL_MESSAGE));
	}

	@Test
	void givenTooShortPassword_whenRegister_thenReturnsBadRequestWithFieldError() throws Exception {
		// given
		var requestBody = registerBody(TestFixtures.TEST_EMAIL, TOO_SHORT_PASSWORD);

		// when
		var result = mockMvc.perform(post(REGISTER_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(requestBody));

		// then
		result.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.message").value(VALIDATION_FAILED_MESSAGE))
				.andExpect(jsonPath("$.errors.password").value(PASSWORD_TOO_SHORT_MESSAGE));
	}

	@Test
	void givenBlankPassword_whenLogin_thenReturnsBadRequestWithFieldError() throws Exception {
		// given
		var requestBody = objectMapper.writeValueAsString(new LoginRequest(TestFixtures.TEST_EMAIL, ""));

		// when
		var result = mockMvc.perform(post(LOGIN_URL)
											 .contentType(MediaType.APPLICATION_JSON)
											 .content(requestBody));

		// then
		result.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.message").value(VALIDATION_FAILED_MESSAGE))
				.andExpect(jsonPath("$.errors.password").value(MUST_NOT_BE_BLANK_MESSAGE));
	}

	@Test
	void givenNoToken_whenRequestingProtectedEndpoint_thenReturnsUnauthorizedWithBearerChallenge() throws Exception {
		// when
		var result = mockMvc.perform(get(ME_URL));

		// then
		result.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(BEARER_CHALLENGE)));
	}

	@Test
	void givenValidToken_whenRequestingProtectedEndpoint_thenReturnsCurrentUserWithMappedAuthorities()
			throws Exception {
		// given
		var token = registerAndReturnToken();

		// when
		var result = mockMvc.perform(get(ME_URL).header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + token));

		// then
		result.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value(TestFixtures.TEST_EMAIL))
				.andExpect(jsonPath("$.authorities").value(hasItem(TestFixtures.USER_AUTHORITY)));
	}

	@Test
	void givenMalformedToken_whenRequestingProtectedEndpoint_thenReturnsUnauthorized() throws Exception {
		// when
		var result = mockMvc.perform(get(ME_URL).header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + MALFORMED_TOKEN));

		// then
		result.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(INVALID_TOKEN_ERROR)));
	}

	@Test
	void givenTokenWithTamperedSignature_whenRequestingProtectedEndpoint_thenReturnsUnauthorized() throws Exception {
		// given
		var tamperedToken = registerAndReturnToken() + SIGNATURE_TAMPER_SUFFIX;

		// when
		var result = mockMvc.perform(get(ME_URL).header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + tamperedToken));

		// then
		result.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(INVALID_TOKEN_ERROR)));
	}

	/**
	 * Documents the price of the self-contained token: nothing is looked up in the database while a request is
	 * authenticated, so a token stays usable until it expires, even after its user is gone.
	 */
	@Test
	void givenTokenOfDeletedUser_whenRequestingProtectedEndpoint_thenTokenIsStillAccepted() throws Exception {
		// given
		var token = registerAndReturnToken();
		userRepository.deleteAll();

		// when
		var result = mockMvc.perform(get(ME_URL).header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + token));

		// then
		result.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value(TestFixtures.TEST_EMAIL));
	}

	private String registerBody(String email, String password) {
		return objectMapper.writeValueAsString(new RegisterRequest(email, password));
	}

	private String registerAndReturnToken() throws Exception {
		var registerResponse = mockMvc.perform(post(REGISTER_URL)
													   .contentType(MediaType.APPLICATION_JSON)
													   .content(registerBody(TestFixtures.TEST_EMAIL,
																			 TestFixtures.TEST_PASSWORD)))
				.andReturn().getResponse().getContentAsString();
		return objectMapper.readTree(registerResponse).get(TOKEN_FIELD).asString();
	}
}
