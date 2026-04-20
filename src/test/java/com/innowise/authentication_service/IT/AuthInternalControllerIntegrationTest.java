package com.innowise.authentication_service.IT;


import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.repository.UserAuthRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthInternalControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAuthRepository userAuthRepository;

    private static final String INTERNAL_KEY = "innowise-secret-internal-key";

    @Test
    void deleteUserSuccess() throws Exception {
        UserAuth user = userAuthRepository.save(
                UserAuth.builder()
                        .login("to-delete")
                        .passwordHash("x")
                        .role(AuthRole.USER)
                        .build()
        );

        mockMvc.perform(delete("/auth/internal/" + user.getId())
                        .header("X-Internal-Key", INTERNAL_KEY))
                .andExpect(status().isOk());

        assertThat(userAuthRepository.findById(user.getId()))
                .isEmpty();
    }

}
