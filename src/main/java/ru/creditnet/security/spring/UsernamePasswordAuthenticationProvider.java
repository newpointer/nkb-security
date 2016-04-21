package ru.creditnet.security.spring;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TicketPrincipal;

import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * @author Maksim Konyuhov
 * @author val
 */
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final SecurityService securityService;

    public UsernamePasswordAuthenticationProvider(SecurityService securityService) {
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

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();

        TicketPrincipal principal = securityService.authenticate(name, password, details.getRemoteAddress());

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                principal, authentication.getCredentials(), getAuthorities(principal));
        return result;
    }

    @Override
    public boolean supports(Class<? extends Object> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Set<GrantedAuthority> getAuthorities(TicketPrincipal principal) {
        return principal.getPermissions().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(toSet());
    }
}
