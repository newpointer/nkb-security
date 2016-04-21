package ru.creditnet.security.web;

import com.jayway.restassured.module.mockmvc.RestAssuredMockMvc;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.context.WebApplicationContext;
import ru.creditnet.security.TestUtils;

import javax.servlet.http.HttpServletResponse;

import static com.jayway.restassured.module.mockmvc.RestAssuredMockMvc.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

/**
 * @author val
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(WebApplication.class)
@WebIntegrationTest(randomPort = true)
public class ControllerTest {

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private FilterChainProxy filterChain;

    private static RequestPostProcessor user(User user) {
        return httpBasic(user.getUsername(), user.getPassword());
    }

    private static RequestPostProcessor user0() {
        return user(TestUtils.user0);
    }

    private static RequestPostProcessor user1() {
        return user(TestUtils.user1);
    }

    @Before
    public void setUp() {
        MockMvc mvc = webAppContextSetup(this.context)
                .addFilters(this.filterChain)
                .build();
        SecurityContextHolder.clearContext();

        RestAssuredMockMvc.enableLoggingOfRequestAndResponseIfValidationFails();
        RestAssuredMockMvc.mockMvc(mvc);
    }

    @Test
    public void shouldBeFiltersIsThree() {
        assertThat(filterChain.getFilterChains()).hasSize(1);
        assertThat(filterChain.getFilterChains().get(0).getFilters()).hasSize(3);
    }

    @Test
    public void shouldBeUnauthorized() throws Exception {
        given()
                .when().get("/anonymous/allow")
                .then().assertThat().statusCode(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void shouldBeUser0Allow() throws Exception {
        given().auth().with(user0())
                .when().get("/user0/allow")
                .then().assertThat()
                .statusCode(HttpServletResponse.SC_OK)
                .and().body(equalTo(Controller.RESULT));
    }

    @Test
    public void shouldBeUser0Deny() throws Exception {
        given().auth().with(user0())
                .when().get("/user0/deny")
                .then().assertThat()
                .statusCode(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void shouldBeUser1Deny() throws Exception {
        given().auth().with(user1())
                .when().get("/user0/allow")
                .then().assertThat()
                .statusCode(HttpServletResponse.SC_FORBIDDEN);
    }
}
