package ru.creditnet.security.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.restassured.module.mockmvc.RestAssuredMockMvc;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpServletResponse;

import static com.jayway.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

/**
 * @author val
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(WebApplication.class)
@WebIntegrationTest(randomPort = true)
@TestPropertySource(locations = "classpath:application-anonymous.properties")
public class ControllerAnonymousTest {

    @Autowired
    WebApplicationContext context;
    @Autowired
    FilterChainProxy filterChain;
    @Autowired
    ObjectMapper objectMapper;

    private MockMvc mvc;

    @Before
    public void setUp() {
        this.mvc = webAppContextSetup(this.context)
                .addFilters(this.filterChain)
                .build();
        SecurityContextHolder.clearContext();

        RestAssuredMockMvc.enableLoggingOfRequestAndResponseIfValidationFails();
        RestAssuredMockMvc.mockMvc(mvc);
    }

    @Test
    public void shouldBeFiltersIsFour() {
        assertThat(filterChain.getFilterChains()).hasSize(1);
        assertThat(filterChain.getFilterChains().get(0).getFilters()).hasSize(4);
    }

    @Test
    public void shouldBeAnonymousAllow() throws Exception {
        given()
                .when().get("/anonymous/allow")
                .then().assertThat().statusCode(HttpServletResponse.SC_OK).and().body(equalTo(Controller.RESULT));
    }

    @Test
    public void shouldBeAnonymousDeny() throws Exception {
        given()
                .when().get("/anonymous/deny")
                .then().assertThat().statusCode(HttpServletResponse.SC_FORBIDDEN);
    }
}