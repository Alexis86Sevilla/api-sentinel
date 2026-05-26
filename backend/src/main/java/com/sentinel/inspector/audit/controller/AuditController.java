package com.sentinel.inspector.audit.controller;

import com.sentinel.inspector.audit.domain.AuditReport;
import com.sentinel.inspector.audit.domain.AuditHeadersService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditHeadersService auditHeadersService;

    public AuditController(AuditHeadersService auditHeadersService) {
        this.auditHeadersService = auditHeadersService;
    }

    @GetMapping("/headers")
    public AuditReport auditHeaders(@RequestParam String url) {
        return auditHeadersService.performAudit(url);
    }
}
