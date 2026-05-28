package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CookieAuditServiceTest {

    private CookieAuditService cookieAuditService;

    @BeforeEach
    void setUp() {
        cookieAuditService = new CookieAuditService();
    }

    @Test
    void shouldCreateServiceInstance() {
        assertNotNull(cookieAuditService);
    }

    @Test
    void shouldReturnValidResultForSecureSite() {
        // Google has good cookie security
        SecurityAuditResult result = cookieAuditService.auditCookies("https://www.google.com");
        
        assertNotNull(result);
        assertTrue(result.score() >= 0 && result.score() <= 100);
        assertEquals(4, result.items().size());
        
        // Check all items are present
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("secure")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("httponly")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("samesite")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("thirdparty")));
    }

    @Test
    void shouldHandleInvalidUrl() {
        SecurityAuditResult result = cookieAuditService.auditCookies("not-a-valid-url");
        
        assertNotNull(result);
        assertEquals(0, result.score());
        assertEquals(4, result.items().size());
    }
}