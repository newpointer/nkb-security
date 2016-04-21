package ru.creditnet.security.impl;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TicketPrincipal;

import java.util.Optional;
import java.util.Set;

/**
 * @author Alexander Yastrebov
 * @author val
 */
public class AnonymousSecurityServiceWrapper implements SecurityService {

    private final AuthenticationTrustResolver anonymousResolver;
    private final SecurityService securityService;

    public AnonymousSecurityServiceWrapper(AuthenticationTrustResolver anonymousResolver, SecurityService securityService) {
        Assert.notNull(anonymousResolver, "anonymousResolver must not be null");
        this.anonymousResolver = anonymousResolver;

        Assert.notNull(securityService, "securityService must not be null");
        this.securityService = securityService;
    }

    @Override
    public TicketPrincipal authenticate(String login, String password, String ip) {
        return securityService.authenticate(login, password, ip);
    }

    @Override
    public TicketPrincipal authenticateWithTicket(String ticket) {
        return securityService.authenticateWithTicket(ticket);
    }

    @Override
    public String getAuthenticatedUserId() {
        return getAuthentication()
                .map(a -> anonymousResolver.isAnonymous(a) ? a.getName() : securityService.getAuthenticatedUserId())
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException(AbstractSecurityService.NOT_AUTHENTICATED));
    }

    @Override
    public Set<String> getAuthenticatedPermissions() {
        return getAuthentication()
                .map(a -> anonymousResolver.isAnonymous(a) ? AuthorityUtils.authorityListToSet(a.getAuthorities()) : securityService.getAuthenticatedPermissions())
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException(AbstractSecurityService.NOT_AUTHENTICATED));
    }

    @Override
    public void ensureHasPermission(String permission) {
        getAuthentication()
                .ifPresent(a -> {
                    if (anonymousResolver.isAnonymous(a)) {
                        if (!AuthorityUtils.authorityListToSet(a.getAuthorities()).contains(permission)) {
                            accessDeniedThrow("Anonymous has no permission " + permission);
                        }
                    } else {
                        securityService.ensureHasPermission(permission);
                    }
                });
    }

    @Override
    public Optional<Authentication> getAuthentication() {
        return securityService.getAuthentication();
    }

    @Override
    public void accessDeniedThrow(String message) {
        securityService.accessDeniedThrow(message);
    }
}
