package ru.creditnet.security.impl;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;
import ru.creditnet.security.TicketPrincipal;

import java.util.UUID;

/**
 * @author Alexander Yastrebov
 * @author ankostyuk
 * @author val
 */
public class SimpleSecurityService extends AbstractSecurityService {

    private static final String TICKET_PREFIX = "ticket_";
    private static final int TICKET_PREFIX_SIZE = TICKET_PREFIX.length() + 37;
    private final UserDetailsService userDetailsService;

    public SimpleSecurityService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "'userDetailsService' must not be null");
        this.userDetailsService = userDetailsService;
    }

    @Override
    public TicketPrincipal authenticate(String login, String password, String ip) {
        logger.debug("authenticate ip: {}", ip);
        UserDetails details = userDetailsService.loadUserByUsername(login);
        if (!details.getPassword().equals(password)) {
            throw new BadCredentialsException("Authentication failed for " + login);
        }

        String userId = details.getUsername();
        String ticket = TICKET_PREFIX + UUID.randomUUID().toString() + "_" + details.getUsername();

        return new TicketPrincipal(userId, ticket, ticket, AuthorityUtils.authorityListToSet(details.getAuthorities()));
    }

    @Override
    public TicketPrincipal authenticateWithTicket(String ticket) {
        if (ticket == null
                || !ticket.startsWith(TICKET_PREFIX)
                || ticket.length() <= TICKET_PREFIX_SIZE) {
            throw new BadCredentialsException("Invalid ticket");
        }
        String userId = ticket.substring(TICKET_PREFIX_SIZE);
        UserDetails details = userDetailsService.loadUserByUsername(userId);

        return new TicketPrincipal(userId, ticket, ticket, AuthorityUtils.authorityListToSet(details.getAuthorities()));
    }

    @Override
    public void logout(TicketPrincipal ticketPrincipal) {
    }
}
