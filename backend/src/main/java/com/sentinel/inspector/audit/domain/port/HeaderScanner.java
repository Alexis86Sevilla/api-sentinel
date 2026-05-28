package com.sentinel.inspector.audit.domain.port;

import java.net.URI;
import java.util.Map;

public interface HeaderScanner {
    Map<String, String> scanHeaders(URI targetUrl);
}