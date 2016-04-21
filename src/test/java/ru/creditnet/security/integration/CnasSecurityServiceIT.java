package ru.creditnet.security.integration;

import creditnet.cnas.auth.SsoTicket;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TicketPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author val
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CnasSecurityServiceITApplication.class)
public class CnasSecurityServiceIT {

    @Autowired
    SecurityService securityService;

    @Value("${test.cnasUsername}")
    String testCnasUsername;
    @Value("${test.cnasPassword}")
    String testCnasPassword;

    @Test
    public void shouldBeAuthenticatedAsCnasUser() throws Exception {
        TicketPrincipal principal = securityService.authenticate(testCnasUsername, testCnasPassword, "127.0.0.1");
        assertThat(principal.getUserId()).isNotNull();
        assertThat(principal.getTicket()).isNotNull().isInstanceOf(SsoTicket.class);

        TicketPrincipal principal0 = securityService.authenticateWithTicket(principal.getTicketId());
        assertThat(principal).isEqualToComparingFieldByFieldRecursively(principal0);
    }
}
