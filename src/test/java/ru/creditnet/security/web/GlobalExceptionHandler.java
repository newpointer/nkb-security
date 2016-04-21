package ru.creditnet.security.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author val
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static void error(HttpServletResponse r, Exception e, HttpStatus status) throws IOException {
        error(r, e, status.value(), status.getReasonPhrase());
    }

    private static void error(HttpServletResponse r, Exception e, int code, String error) throws IOException {
        r.setStatus(code);
        r.getWriter().print(error);
        logger.info("API exception was thrown: {}: {}", e.getClass().getCanonicalName(), e.getMessage());
        logger.debug("", e);
    }

    @ExceptionHandler(AuthenticationCredentialsNotFoundException.class)
    public void handleAuthenticationCredentialsNotFoundException(AuthenticationCredentialsNotFoundException e, HttpServletResponse response) throws IOException {
        error(response, e, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public void handleAccessDeniedException(AccessDeniedException e, HttpServletResponse response) throws IOException {
        error(response, e, HttpStatus.FORBIDDEN);
    }
}
