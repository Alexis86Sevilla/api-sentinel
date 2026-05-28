package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SslInfoServiceTest {

    private SslInfoService sslInfoService;

    @BeforeEach
    void setUp() {
        sslInfoService = new SslInfoService();
    }

    @Test
    void shouldCreateServiceInstance() {
        assertNotNull(sslInfoService);
    }

    @Test
    void shouldReturnSslInfoWithScoreForValidHttpsUrl() {
        String testUrl = "https://www.google.com";
        
        SecurityAuditResult result = sslInfoService.getSslInfo(testUrl);
        
        assertNotNull(result);
        assertTrue(result.score() >= 0 && result.score() <= 100, 
            "Score should be between 0 and 100");
        assertEquals(4, result.items().size(), "Should return 4 SSL info items");
        
        result.items().forEach(item -> {
            assertNotNull(item.key(), "Key should not be null");
            assertNotNull(item.label(), "Label should not be null");
            assertNotNull(item.value(), "Value should not be null");
            assertNotNull(item.status(), "Status should not be null");
        });
        
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("certificate")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("protocol")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("expiration")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("cipher")));
        
        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("valid", certificate.status());
        assertTrue(certificate.value().contains("Válido"));
    }

    @Test
    void shouldHandleUrlWithoutProtocol() {
        String testUrl = "www.google.com";
        
        SecurityAuditResult result = sslInfoService.getSslInfo(testUrl);
        
        assertNotNull(result);
        assertNotNull(result.score());
        assertEquals(4, result.items().size());
    }

    @Test
    void shouldHandleHttpUrl() {
        String testUrl = "http://www.google.com";
        
        SecurityAuditResult result = sslInfoService.getSslInfo(testUrl);
        
        assertNotNull(result);
        assertNotNull(result.score());
        assertEquals(4, result.items().size());
    }

    @Test
    void shouldReturnZeroScoreForInvalidUrl() {
        String testUrl = "not-a-valid-url-12345.xyz";
        
        SecurityAuditResult result = sslInfoService.getSslInfo(testUrl);
        
        assertNotNull(result);
        assertEquals(0, result.score(), "Score should be 0 for invalid domain");
        assertEquals(4, result.items().size());
        
        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("error", certificate.status());
        assertTrue(certificate.value().startsWith("Error:"));
    }
}