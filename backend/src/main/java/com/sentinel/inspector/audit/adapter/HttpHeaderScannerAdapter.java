package com.sentinel.inspector.audit.adapter;

import com.sentinel.inspector.audit.domain.AuditReport;
import com.sentinel.inspector.audit.domain.ports.HeaderScanner;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

public class HttpHeaderScannerAdapter implements HeaderScanner {

    private final HttpClient httpClient;

    public HttpHeaderScannerAdapter() {
        this.httpClient = HttpClient.newBuilder().build();
    }

    @Override
    public AuditReport scanHeaders(URI targetUrl) {
        System.out.println("Scanning headers for URL: " + targetUrl.toString());

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(targetUrl)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            Map<String, String> headers = response.headers().map().entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey(),
                            entry -> entry.getValue().get(0) // Tomamos el primer valor si hay múltiples
                    ));

            return new AuditReport(targetUrl.toString(), LocalDateTime.now(), headers, Collections.emptyList(), 0);

        } catch (IOException | InterruptedException e) {
            System.err.println("Error during HTTP header scan for " + targetUrl + ": " + e.getMessage());
            // En caso de error, devolvemos un reporte con un problema indicando el error.
            return new AuditReport(
                    targetUrl.toString(),
                    LocalDateTime.now(),
                    Collections.emptyMap(),
                    List.of("Error scanning headers: " + e.getMessage()),
                    0
            );
        }
    }
}
