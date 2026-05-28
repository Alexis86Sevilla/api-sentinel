package com.sentinel.inspector.audit;

import com.sentinel.inspector.audit.application.AuditHeadersService;
import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import com.sentinel.inspector.audit.infrastructure.adapter.HttpHeaderScannerAdapter;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class HeaderAuditIntegrationTest {

    private MockWebServer mockWebServer;
    private HttpHeaderScannerAdapter httpHeaderScannerAdapter;
    private AuditHeadersService auditHeadersService;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        httpHeaderScannerAdapter = new HttpHeaderScannerAdapter();
        auditHeadersService = new AuditHeadersService(httpHeaderScannerAdapter);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    @DisplayName("Should pass audit for headers with valid security configurations")
    void shouldPassAuditWithValidSecurityHeaders() {
        String mockUrl = mockWebServer.url("/").toString();

        mockWebServer.enqueue(new MockResponse()
                .addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                .addHeader("Content-Security-Policy", "default-src 'self'")
                .addHeader("X-Frame-Options", "DENY")
                .addHeader("X-Content-Type-Options", "nosniff")
                .addHeader("Referrer-Policy", "no-referrer")
                .setResponseCode(200));

        SecurityAuditResult report = auditHeadersService.performAudit(mockUrl);

        assertNotNull(report);
        assertEquals(100, report.score(), "Score should be 100 for valid headers.");
        assertFalse(report.items().isEmpty(), "Items should not be empty");

        List<SecurityItem> items = report.items();
        assertTrue(items.stream().anyMatch(item -> item.key().equals("strict-transport-security") && item.status().equals("success")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("content-security-policy") && item.status().equals("success")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-frame-options") && item.status().equals("success")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-content-type-options") && item.status().equals("success")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("referrer-policy") && item.status().equals("success")));
    }

    @Test
    @DisplayName("Should report issues for missing security headers")
    void shouldReportIssuesForMissingSecurityHeaders() {
        String mockUrl = mockWebServer.url("/").toString();

        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200));

        SecurityAuditResult report = auditHeadersService.performAudit(mockUrl);

        assertNotNull(report);
        assertTrue(report.score() < 100, "Score should be reduced for missing headers.");

        List<SecurityItem> items = report.items();
        assertTrue(items.stream().anyMatch(item -> item.key().equals("strict-transport-security") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("content-security-policy") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-frame-options") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-content-type-options") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("referrer-policy") && item.status().equals("warning")));
    }

    @Test
    @DisplayName("Should report issues for invalid security header values")
    void shouldReportIssuesForInvalidSecurityHeaderValues() {
        String mockUrl = mockWebServer.url("/").toString();

        mockWebServer.enqueue(new MockResponse()
                .addHeader("Strict-Transport-Security", "max-age=1000")
                .addHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
                .addHeader("X-Frame-Options", "ALLOW-FROM http://bad.com")
                .addHeader("X-Content-Type-Options", "sniff")
                .addHeader("Referrer-Policy", "unsafe-url")
                .setResponseCode(200));

        SecurityAuditResult report = auditHeadersService.performAudit(mockUrl);

        assertNotNull(report);
        assertTrue(report.score() < 100, "Score should be reduced for invalid header values.");

        List<SecurityItem> items = report.items();
        assertTrue(items.stream().anyMatch(item -> item.key().equals("strict-transport-security") && item.status().equals("warning")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("content-security-policy") && item.status().equals("warning")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-frame-options") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("x-content-type-options") && item.status().equals("error")));
        assertTrue(items.stream().anyMatch(item -> item.key().equals("referrer-policy") && item.status().equals("warning")));
    }
}