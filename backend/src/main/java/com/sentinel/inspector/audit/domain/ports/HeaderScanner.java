package com.sentinel.inspector.audit.domain.ports;

import com.sentinel.inspector.audit.domain.AuditReport;

import java.net.URI;

public interface HeaderScanner {
    AuditReport scanHeaders(URI targetUrl);
}