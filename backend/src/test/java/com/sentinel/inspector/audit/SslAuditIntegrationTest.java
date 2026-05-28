package com.sentinel.inspector.audit;

import com.sentinel.inspector.audit.application.SslInfoService;
import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SslAuditIntegrationTest {

    private SslInfoService sslInfoService;

    @BeforeEach
    void setUp() {
        sslInfoService = new SslInfoService();
    }

    @Test
    @DisplayName("Should retrieve valid SSL info with score from Google HTTPS endpoint")
    void shouldRetrieveValidSslInfoFromGoogle() {
        SecurityAuditResult result = sslInfoService.getSslInfo("https://www.google.com");

        assertNotNull(result);
        assertNotNull(result.score());
        assertTrue(result.score() >= 0 && result.score() <= 100, 
            "Score should be between 0 and 100");
        assertEquals(4, result.items().size(), "Should return 4 SSL info items");

        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("valid", certificate.status());
        assertTrue(certificate.value().startsWith("Válido"), "Certificate should be valid");
        assertTrue(certificate.value().contains("SHA"), "Should include hash algorithm");

        SecurityItem protocol = result.items().stream()
            .filter(i -> i.key().equals("protocol"))
            .findFirst()
            .orElseThrow();
        assertTrue(protocol.status().equals("valid") || protocol.status().equals("warning"));
        assertTrue(protocol.value().contains("TLS"), "Should include TLS version");

        SecurityItem expiration = result.items().stream()
            .filter(i -> i.key().equals("expiration"))
            .findFirst()
            .orElseThrow();
        assertTrue(expiration.status().equals("valid") || expiration.status().equals("warning"));
        assertTrue(expiration.value().contains("días"), "Should show days until expiration");

        SecurityItem cipher = result.items().stream()
            .filter(i -> i.key().equals("cipher"))
            .findFirst()
            .orElseThrow();
        assertNotNull(cipher.value());
        assertFalse(cipher.value().isEmpty());
    }

    @Test
    @DisplayName("Should handle HTTP URLs by converting to HTTPS")
    void shouldHandleHttpUrls() {
        SecurityAuditResult result = sslInfoService.getSslInfo("http://www.google.com");

        assertNotNull(result);
        assertNotNull(result.score());
        assertEquals(4, result.items().size());

        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("valid", certificate.status());
    }

    @Test
    @DisplayName("Should handle URLs without protocol")
    void shouldHandleUrlsWithoutProtocol() {
        SecurityAuditResult result = sslInfoService.getSslInfo("www.google.com");

        assertNotNull(result);
        assertNotNull(result.score());
        assertEquals(4, result.items().size());

        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("valid", certificate.status());
    }

    @Test
    @DisplayName("Should return zero score for invalid domains")
    void shouldReturnZeroScoreForInvalidDomains() {
        SecurityAuditResult result = sslInfoService.getSslInfo("https://invalid-domain-12345.test");

        assertNotNull(result);
        assertEquals(0, result.score(), "Score should be 0 for invalid domain");
        assertEquals(4, result.items().size());

        SecurityItem certificate = result.items().stream()
            .filter(i -> i.key().equals("certificate"))
            .findFirst()
            .orElseThrow();
        assertEquals("error", certificate.status());
        assertTrue(certificate.value().startsWith("Error:"), "Should indicate error");
    }
}