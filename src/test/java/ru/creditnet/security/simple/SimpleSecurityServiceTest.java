package ru.creditnet.security.simple;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TestUtils;
import ru.creditnet.security.TicketPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author val
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(SimpleSecurityServiceTestApplication.class)
public class SimpleSecurityServiceTest {

    @Autowired
    SecurityService securityService;

    @Test
    public void shouldBeAuthenticated() throws Exception {
        User user = TestUtils.user0;
        TicketPrincipal principal = securityService.authenticate(user.getUsername(), user.getPassword(), "127.0.0.1");
        assertThat(principal.getUserId()).isNotNull().isEqualTo(user.getUsername());
        assertThat(principal.getTicket()).isNotNull().isInstanceOf(String.class);

        TicketPrincipal principal0 = securityService.authenticateWithTicket(principal.getTicketId());
        assertThat(principal).isEqualToComparingFieldByFieldRecursively(principal0);

        assertThat(securityService.getAuthentication()).isNotPresent();
    }

    @Test(expected = BadCredentialsException.class)
    public void shouldBeBadCredentials() throws Exception {
        User user = TestUtils.user0;
        securityService.authenticate(user.getUsername(), "broteforce", "127.0.0.1");
    }

    @Test(expected = UsernameNotFoundException.class)
    public void shouldBeUsernameNotFound() {
        securityService.authenticate("unknownUser", "broteforce", "127.0.0.1");
    }
}
