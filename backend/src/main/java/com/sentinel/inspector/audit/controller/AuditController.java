package com.sentinel.inspector.audit.controller;

import com.sentinel.inspector.audit.application.AuditHeadersService;
import com.sentinel.inspector.audit.application.CookieAuditService;
import com.sentinel.inspector.audit.application.ServerConfigAuditService;
import com.sentinel.inspector.audit.application.SslInfoService;
import com.sentinel.inspector.audit.application.VulnerabilityAuditService;
import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/audit")
@CrossOrigin(origins = "*")
public class AuditController {

    private final AuditHeadersService auditHeadersService;
    private final SslInfoService sslInfoService;
    private final CookieAuditService cookieAuditService;
    private final VulnerabilityAuditService vulnerabilityAuditService;
    private final ServerConfigAuditService serverConfigAuditService;

    public AuditController(
            AuditHeadersService auditHeadersService, 
            SslInfoService sslInfoService,
            CookieAuditService cookieAuditService,
            VulnerabilityAuditService vulnerabilityAuditService,
            ServerConfigAuditService serverConfigAuditService) {
        this.auditHeadersService = auditHeadersService;
        this.sslInfoService = sslInfoService;
        this.cookieAuditService = cookieAuditService;
        this.vulnerabilityAuditService = vulnerabilityAuditService;
        this.serverConfigAuditService = serverConfigAuditService;
    }

    @GetMapping("/headers")
    public SecurityAuditResult auditHeaders(@RequestParam String url) {
        return auditHeadersService.performAudit(url);
    }

    @GetMapping("/ssl")
    public SecurityAuditResult auditSsl(@RequestParam String url) {
        return sslInfoService.getSslInfo(url);
    }

    @GetMapping("/cookies")
    public SecurityAuditResult auditCookies(@RequestParam String url) {
        return cookieAuditService.auditCookies(url);
    }

    @GetMapping("/vulnerabilities")
    public SecurityAuditResult auditVulnerabilities(@RequestParam String url) {
        return vulnerabilityAuditService.auditVulnerabilities(url);
    }

    @GetMapping("/server-config")
    public SecurityAuditResult auditServerConfig(@RequestParam String url) {
        return serverConfigAuditService.auditServerConfig(url);
    }
}