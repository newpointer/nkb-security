package ru.creditnet.security.spring;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TicketPrincipal;

import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * @author Alexander Yastrebov
 * @author val
 */
public class TicketAuthenticationProvider implements AuthenticationProvider {

    private final SecurityService securityService;

    public TicketAuthenticationProvider(SecurityService securityService) {
        Assert.notNull(securityService, "Security service must not be null");
        this.securityService = securityService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication.getPrincipal() == null) {
            throw new BadCredentialsException("No principal found in request");
        }

        TicketPrincipal principal = securityService.authenticateWithTicket(authentication.getPrincipal().toString());
        if (principal == null) {
            throw new BadCredentialsException("Principal is null");
        }

        PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(
                principal, authentication.getCredentials(), getAuthorities(principal));
        result.setDetails(authentication.getDetails());

        return result;
    }

    @Override
    public boolean supports(Class<? extends Object> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Set<GrantedAuthority> getAuthorities(TicketPrincipal principal) {
        return principal.getPermissions().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(toSet());
    }
}
