package ru.creditnet.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static ru.creditnet.security.Permissions.*;

/**
 * @author val
 */
public class TestUtils {

    // application-anonymous.properties
    public static final User anonymous = new User("anonymous", "anonymous", authorities(SEARCH));

    public static final User user0 = new User("user0", "user0", authorities(DATA_VIEWFULL, SEARCH_RELATED, REPORT_SAVE));
    public static final User user1 = new User("user1", "user1", authorities(SEARCH_TRACES));
    public static final UserDetailsService userDetailsService = new InMemoryUserDetailsManager(Arrays.asList(user0, user1));

    private static List<String> permissionsExcept(User user) {
        List<String> permissions = Stream.of(Permissions.stringValues()).collect(toList());
        List<String> permissionsUser = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());
        permissions.removeAll(permissionsUser);
        return permissions;
    }

    public static String permissionExcept(User user) {
        return permissionsExcept(user).get(0);
    }

    public static String permission(User user) {
        return user.getAuthorities().iterator().next().getAuthority();
    }

    private static Collection<? extends GrantedAuthority> authorities(Permissions... authorities) {
        return Stream.of(authorities)
                .map(Permissions::name)
                .map(SimpleGrantedAuthority::new)
                .collect(toList());
    }
}
