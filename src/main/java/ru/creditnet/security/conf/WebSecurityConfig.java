package ru.creditnet.security.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import ru.creditnet.security.Permissions;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.spring.EmptyBodyBasicAuthenticationEntryPoint;
import ru.creditnet.security.spring.RequestCookieAuthenticationFilter;
import ru.creditnet.security.spring.TicketAuthenticationProvider;
import ru.creditnet.security.spring.UsernamePasswordAuthenticationProvider;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

import static java.util.stream.Collectors.toList;

/**
 * @author val
 */
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@EnableConfigurationProperties({ConfigProperties.class, SecurityProperties.class})
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public SecurityService securityService;
    @Autowired
    public ConfigProperties properties;
    @Autowired
    public SecurityProperties securityProperties;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
//                .authenticationProvider(new AnonymousAuthenticationProvider("anonymous-key"))
                .authenticationProvider(new TicketAuthenticationProvider(securityService))
                .authenticationProvider(new UsernamePasswordAuthenticationProvider(securityService))
        ;
    }

    private AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {
        web.ignoring().antMatchers(securityProperties.getIgnored().toArray(new String[0]));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (!properties.getAnonymousPermissions().isEmpty()) {
            List<GrantedAuthority> authorities = properties.getAnonymousPermissions()
                    .stream()
                    .map(Permissions::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(toList());
            http.anonymous().key("anonymous-key").principal("anonymousUser").authorities(authorities);
            http.authorizeRequests().antMatchers(securityProperties.getBasic().getPath()).permitAll();
        } else {
            http.anonymous().disable();
        }
        http
                .csrf().disable()
                .addFilterAfter(requestCookieAuthenticationFilter(), SecurityContextPersistenceFilter.class)
                .exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint()).and()
                .authorizeRequests().anyRequest().authenticated().and()
                .httpBasic().authenticationEntryPoint(basicAuthenticationEntryPoint())
        ;
    }

    private RequestCookieAuthenticationFilter requestCookieAuthenticationFilter() throws Exception {
        RequestCookieAuthenticationFilter requestCookieAuthenticationFilter = new RequestCookieAuthenticationFilter(properties.getCnasTicketCookieName());
        requestCookieAuthenticationFilter.setAuthenticationManager(authenticationManager());
        requestCookieAuthenticationFilter.setCheckForPrincipalChanges(true);
        requestCookieAuthenticationFilter.afterPropertiesSet();
        return requestCookieAuthenticationFilter;
    }

    private BasicAuthenticationEntryPoint basicAuthenticationEntryPoint() throws Exception {
        EmptyBodyBasicAuthenticationEntryPoint entryPoint = new EmptyBodyBasicAuthenticationEntryPoint();
        entryPoint.setRealmName("connections");
        entryPoint.afterPropertiesSet();
        return entryPoint;
    }
}
