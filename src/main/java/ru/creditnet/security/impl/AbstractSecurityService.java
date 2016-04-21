package ru.creditnet.security.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TicketPrincipal;

import java.util.Optional;
import java.util.Set;

/**
 * @author Alexander Yastrebov
 * @author val
 */
abstract class AbstractSecurityService implements SecurityService {

    public static final String NOT_AUTHENTICATED = "Not authenticated";
    private static final String ACCESS_DENIED = "Access denied";
    //    static final AuthenticationCredentialsNotFoundException AUTHENTICATION_CREDENTIALS_NOT_FOUND_EXCEPTION = new AuthenticationCredentialsNotFoundException(NOT_AUTHENTICATED);
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public String getAuthenticatedUserId() {
        Optional<Authentication> o = getAuthentication();
        if (o.isPresent()) {
            Object principal = o.get().getPrincipal();
            if (TicketPrincipal.class.isInstance(principal)) {
                return TicketPrincipal.class.cast(principal).getUserId();
            }
            if (User.class.isInstance(principal)) {
                return User.class.cast(principal).getUsername();
            }
        }
        throw new AuthenticationCredentialsNotFoundException(NOT_AUTHENTICATED);
    }

//    @Override
//    public String getAuthenticatedUserId() {
//        return getAuthentication()
//                .map(Authentication::getPrincipal)
//                .map(p -> (TicketPrincipal) p)
//                .map(TicketPrincipal::getUserId)
//                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException(NOT_AUTHENTICATED));
//    }

    @Override
    public Set<String> getAuthenticatedPermissions() {
        return getAuthentication()
                .map(Authentication::getAuthorities)
                .map(a -> AuthorityUtils.authorityListToSet(a))
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException(NOT_AUTHENTICATED));
    }

    @Override
    public Optional<Authentication> getAuthentication() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());
    }

    @Override
    public void ensureHasPermission(String permission) {
        Assert.hasText(permission);
        if (!getAuthenticatedPermissions().contains(permission)) {
            accessDeniedThrow("Not enough permissions");
        }
    }

    @Override
    public void accessDeniedThrow(String message) {
        throw new AccessDeniedException(Optional.ofNullable(message).orElse(ACCESS_DENIED));
    }
}
