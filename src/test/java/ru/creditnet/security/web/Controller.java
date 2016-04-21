package ru.creditnet.security.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.TestUtils;

/**
 * @author val
 */
@RestController
public class Controller {

    public static final String RESULT = "qwerty";

    @Autowired
    private SecurityService securityService;

    @RequestMapping("/anonymous/allow")
    public ResponseEntity<String> permissionAnonymousAllow() {
        String permission = TestUtils.permission(TestUtils.anonymous);
        Assert.notNull(permission);

        securityService.ensureHasPermission(permission);
        return ResponseEntity.ok(RESULT);
    }

    @RequestMapping("/anonymous/deny")
    public ResponseEntity<String> permissionAnonymousDeny() {
        String permission = TestUtils.permissionExcept(TestUtils.anonymous);
        Assert.notNull(permission);

        securityService.ensureHasPermission(permission);
        return ResponseEntity.ok(RESULT);
    }

    @RequestMapping("/user0/allow")
    public ResponseEntity<String> permission4User0Allow() {
        String permission = TestUtils.permission(TestUtils.user0);
        Assert.notNull(permission);

        securityService.ensureHasPermission(permission);
        return ResponseEntity.ok(RESULT);
    }

    @RequestMapping("/user0/deny")
    public ResponseEntity<String> permission4User0Deny() {
        String permission = TestUtils.permissionExcept(TestUtils.user0);
        Assert.notNull(permission);

        securityService.ensureHasPermission(permission);
        return ResponseEntity.ok(RESULT);
    }
}
