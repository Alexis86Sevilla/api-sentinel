package com.sentinel.inspector.audit.config;

import com.sentinel.inspector.audit.adapter.HttpHeaderScannerAdapter;
import com.sentinel.inspector.audit.domain.AuditHeadersService;
import com.sentinel.inspector.audit.domain.ports.HeaderScanner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuditConfig {

    @Bean
    public HeaderScanner headerScanner() {
        return new HttpHeaderScannerAdapter();
    }

    @Bean
    public AuditHeadersService auditHeadersService(HeaderScanner headerScanner) {
        return new AuditHeadersService(headerScanner);
    }
}
