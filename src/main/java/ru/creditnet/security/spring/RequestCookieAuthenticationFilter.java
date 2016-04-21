package ru.creditnet.security.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Alexander Yastrebov
 * @author val
 */
public class RequestCookieAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(RequestCookieAuthenticationFilter.class);
    private final String principalRequestCookie;

    public RequestCookieAuthenticationFilter(String principalRequestCookie) {
        Assert.notNull(principalRequestCookie, "'principalRequestCookie' must not be null");
        this.principalRequestCookie = principalRequestCookie;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        if (logger.isDebugEnabled()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            logger.debug("auth: {}", auth);
            if (auth != null) {
                logger.debug("auth name: {}", auth.getName());
            }
        }
        Cookie[] cc = request.getCookies();
        if (cc != null) {
            for (Cookie c : cc) {
                if (principalRequestCookie.equals(c.getName())) {
                    String result = c.getValue();

                    logger.debug("Found {} cookie: {}", principalRequestCookie, result);

                    return result;
                }
            }
        }
        logger.debug("No cookie {} found", principalRequestCookie);

        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest hsr) {
        return "N/A";
    }
}
