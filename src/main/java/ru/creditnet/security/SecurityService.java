package ru.creditnet.security;

import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;

/**
 * @author Alexander Yastrebov
 * @author ankostyuk
 */
public interface SecurityService {

    TicketPrincipal authenticate(String login, String password, String ip);

    TicketPrincipal authenticateWithTicket(String ticket);

    String getAuthenticatedUserId();

    Set<String> getAuthenticatedPermissions();

    Optional<Authentication> getAuthentication();

    void ensureHasPermission(String permission);

    void accessDeniedThrow(String message);
}
