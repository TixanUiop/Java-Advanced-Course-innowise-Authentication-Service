package com.innowise.authentication_service.IT;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authentication_service.dto.AuthRequest;
import com.innowise.authentication_service.dto.AuthResponse;
import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.repository.UserAuthRepository;
import com.innowise.authentication_service.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DisplayName("IT AuthController")
class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAuthRepository userAuthRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    private static final String TEST_LOGIN = "testuser";
    private static final String TEST_PASSWORD = "password123";

    private static final String ADMIN_LOGIN = "adm";
    private static final String ADMIN_PASSWORD = "adm123";

    @BeforeEach
    void setUp() {

        userAuthRepository.deleteAll();

        UserAuth testUser = UserAuth.builder()
                .login(TEST_LOGIN)
                .passwordHash(passwordEncoder.encode(TEST_PASSWORD))
                .role(AuthRole.USER)
                .build();
        userAuthRepository.save(testUser);

        UserAuth admin = UserAuth.builder()
                .login(ADMIN_LOGIN)
                .passwordHash(passwordEncoder.encode(ADMIN_PASSWORD))
                .role(AuthRole.ADMIN)
                .build();
        userAuthRepository.save(admin);

        assertThat(userAuthRepository.findByLogin(TEST_LOGIN)).isPresent();
        assertThat(userAuthRepository.findByLogin(ADMIN_LOGIN)).isPresent();
    }

    @Test
    @DisplayName("POST /auth/register - Success registration a new user")
    void registerSuccess() throws Exception {

        AuthRequest request = new AuthRequest("newuser", "newpassword123");

        MvcResult result = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                AuthResponse.class
        );

        assertThatCode(() -> jwtUtil.validateToken(response.getAccessToken()))
                .doesNotThrowAnyException();

        assertThatCode(() -> jwtUtil.validateToken(response.getRefreshToken()))
                .doesNotThrowAnyException();

        Claims accessClaims = jwtUtil.validateToken(response.getAccessToken());
        Claims refreshClaims = jwtUtil.validateToken(response.getRefreshToken());

        assertThat(accessClaims.getSubject()).isNotNull();
        assertThat(accessClaims.get("role")).isEqualTo("USER");
        assertThat(accessClaims.getExpiration()).isAfter(new Date());

        UserAuth savedUser = userAuthRepository.findByLogin("newuser").orElseThrow();
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getLogin()).isEqualTo("newuser");
        assertThat(passwordEncoder.matches("newpassword123", savedUser.getPasswordHash())).isTrue();
        assertThat(savedUser.getRole()).isEqualTo(AuthRole.USER);

        Long userIdFromToken = Long.parseLong(accessClaims.getSubject());
        assertThat(userIdFromToken).isEqualTo(savedUser.getId());
    }


    @Test
    void loginSuccess() throws Exception {
        AuthRequest request = new AuthRequest(TEST_LOGIN, TEST_PASSWORD);

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();

        AuthResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                AuthResponse.class
        );

        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getRefreshToken()).isNotBlank();

        assertThatCode(() -> jwtUtil.validateToken(response.getAccessToken()))
                .doesNotThrowAnyException();
        assertThatCode(() -> jwtUtil.validateToken(response.getRefreshToken()))
                .doesNotThrowAnyException();

        Long userIdFromToken = jwtUtil.extractUserId(response.getAccessToken());
        UserAuth user = userAuthRepository.findByLogin(TEST_LOGIN).orElseThrow();
        assertThat(userIdFromToken).isEqualTo(user.getId());

        String roleFromToken = jwtUtil.extractRole(response.getAccessToken());
        assertThat(roleFromToken).isEqualTo(AuthRole.USER.toString());
    }

    @Test
    void loginInvalidPasswordThrowsException() throws Exception {
        AuthRequest request = new AuthRequest(TEST_LOGIN, "wrongpassword");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Invalid credentials")));
    }

    @Test
    void loginUserNotFoundThrowsException() throws Exception {
        AuthRequest request = new AuthRequest("nonexistent", TEST_PASSWORD);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Invalid credentials")));
    }

    @Test
    void validateTokenValidTokenReturnsValid() throws Exception {
        AuthRequest request = new AuthRequest(TEST_LOGIN, TEST_PASSWORD);
        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse authResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                AuthResponse.class
        );

        mockMvc.perform(post("/auth/validate")
                        .param("token", authResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("valid"));
    }


    @Test
    void validateTokenExpiredTokenThrowsException() throws Exception {
        AuthRequest request = new AuthRequest(TEST_LOGIN, TEST_PASSWORD);
        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse authResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                AuthResponse.class
        );
    }


}