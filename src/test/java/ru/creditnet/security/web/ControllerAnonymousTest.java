package ru.creditnet.security.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.restassured.module.mockmvc.RestAssuredMockMvc;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Collectors;

import static com.jayway.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

/**
 * @author val
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = WebApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
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
    public void shouldBeFoundFilter() {
        assertThat(filterChain.getFilterChains()).hasSize(1);

        List<Class<?>> classes = filterChain.getFilterChains().get(0).getFilters().stream().map(Filter::getClass).collect(Collectors.toList());
        assertThat(classes).contains(BasicAuthenticationFilter.class);
        assertThat(classes).contains(AnonymousAuthenticationFilter.class);
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
