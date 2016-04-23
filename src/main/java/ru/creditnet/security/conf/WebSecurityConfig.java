package ru.creditnet.security.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.creditnet.security.Permissions;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.impl.AnonymousSecurityServiceWrapper;
import ru.creditnet.security.spring.EmptyBodyBasicAuthenticationEntryPoint;
import ru.creditnet.security.spring.RequestCookieAuthenticationFilter;
import ru.creditnet.security.spring.TicketAuthenticationProvider;
import ru.creditnet.security.spring.UsernamePasswordAuthenticationProvider;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

import static java.util.stream.Collectors.toList;

/**
 * @author val
 */
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public SecurityService securityService;

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

    @Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
    public FilterChainProxy springSecurityFilterChain(ConfigProperties properties) throws Exception {
//        AuthenticationManager authenticationManager = authenticationManager();
        List<Filter> filters = new ArrayList<>();
        // SecurityContextPersistenceFilter
        SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter(new HttpSessionSecurityContextRepository());
        filters.add(securityContextPersistenceFilter);
        securityContextPersistenceFilter.afterPropertiesSet();
        // RequestCookieAuthenticationFilter
        RequestCookieAuthenticationFilter requestCookieAuthenticationFilter = new RequestCookieAuthenticationFilter(properties.getCnasTicketCookieName());
        filters.add(requestCookieAuthenticationFilter);
        requestCookieAuthenticationFilter.setAuthenticationManager(authenticationManager());
        requestCookieAuthenticationFilter.setCheckForPrincipalChanges(true);
        requestCookieAuthenticationFilter.afterPropertiesSet();
        // BasicAuthenticationFilter
        EmptyBodyBasicAuthenticationEntryPoint entryPoint = new EmptyBodyBasicAuthenticationEntryPoint();
        entryPoint.setRealmName("connections");
        entryPoint.afterPropertiesSet();
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager(), entryPoint);
        filters.add(basicAuthenticationFilter);
        basicAuthenticationFilter.afterPropertiesSet();
        // AnonymousAuthenticationFilter
        if (!properties.getAnonymousPermissions().isEmpty()) {
            List<GrantedAuthority> authorities = properties.getAnonymousPermissions()
                    .stream()
                    .map(Permissions::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(toList());
            AnonymousAuthenticationFilter anonymousAuthenticationFilter = new AnonymousAuthenticationFilter("anonymous-key", "anonymousUser", authorities);
            filters.add(anonymousAuthenticationFilter);
            anonymousAuthenticationFilter.afterPropertiesSet();
        }
        // FilterSecurityInterceptor
//        SecurityExpressionHandler<FilterInvocation> securityExpressionHandler = new DefaultWebSecurityExpressionHandler();
//        List<AccessDecisionVoter<?>> voters = Arrays.asList(new RoleVoter(), new WebExpressionVoter());
//        AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
//        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
//        filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
//        filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager);
//        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> map = new LinkedHashMap<>();
//        map.put(new AntPathRequestMatcher("/**"), Arrays.<ConfigAttribute>asList(new SecurityConfig("isAuthenticated()")));
//        ExpressionBasedFilterInvocationSecurityMetadataSource ms = new ExpressionBasedFilterInvocationSecurityMetadataSource(map, securityExpressionHandler);
//        filterSecurityInterceptor.setSecurityMetadataSource(ms);
//        filterSecurityInterceptor.afterPropertiesSet();
//        filters.add(filterSecurityInterceptor);

        SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher(properties.getSecurityFilterUrlPattern()), filters);
        return new FilterChainProxy(chain);
    }

    protected SecurityService wrapSecurityService(SecurityService securityService, ConfigProperties configProperties) {
        if (!configProperties.getAnonymousPermissions().isEmpty()) {
            AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
            securityService = new AnonymousSecurityServiceWrapper(authenticationTrustResolver, securityService);
        }
        return securityService;
    }
}
