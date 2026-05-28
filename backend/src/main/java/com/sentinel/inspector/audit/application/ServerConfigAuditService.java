package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class ServerConfigAuditService {

    public SecurityAuditResult auditServerConfig(String url) {
        List<SecurityItem> items = new ArrayList<>();
        int score = 100;

        try {
            // Verificar HTTPS
            HttpsCheckResult httpsResult = checkHttps(url);
            score += httpsResult.score;
            items.add(new SecurityItem(
                "https",
                "HTTPS",
                httpsResult.value,
                httpsResult.status
            ));

            // Verificar redirección HTTP → HTTPS
            RedirectCheckResult redirectResult = checkHttpToHttpsRedirect(url);
            score += redirectResult.score;
            items.add(new SecurityItem(
                "redirect",
                "Redirección HTTP",
                redirectResult.value,
                redirectResult.status
            ));

            // Verificar compresión GZIP
            CompressionCheckResult compressionResult = checkGzipCompression(url);
            score += compressionResult.score;
            items.add(new SecurityItem(
                "compression",
                "Compresión GZIP",
                compressionResult.value,
                compressionResult.status
            ));

            // Verificar listado de directorios
            DirectoryListingCheckResult dirListingResult = checkDirectoryListing(url);
            score += dirListingResult.score;
            items.add(new SecurityItem(
                "directory-listing",
                "Listado de directorios",
                dirListingResult.value,
                dirListingResult.status
            ));

        } catch (Exception e) {
            score = 50;
            items.add(new SecurityItem("https", "HTTPS", "No verificable", "warning"));
            items.add(new SecurityItem("redirect", "Redirección HTTP", "No verificable", "warning"));
            items.add(new SecurityItem("compression", "Compresión GZIP", "No verificable", "warning"));
            items.add(new SecurityItem("directory-listing", "Listado de directorios", "No verificable", "warning"));
        }

        score = Math.max(0, Math.min(100, score));
        return new SecurityAuditResult(score, items);
    }

    private HttpsCheckResult checkHttps(String url) {
        try {
            if (url.startsWith("https://")) {
                // Ya es HTTPS, verificar que funcione
                HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
                
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();
                
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() < 400) {
                    return new HttpsCheckResult("Habilitado", "valid", 10);
                } else {
                    return new HttpsCheckResult("Error SSL", "error", -20);
                }
            } else {
                // Intentar con HTTPS
                String httpsUrl = url.replace("http://", "https://");
                if (!httpsUrl.startsWith("https://")) {
                    httpsUrl = "https://" + httpsUrl;
                }
                
                HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
                
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(httpsUrl))
                    .GET()
                    .build();
                
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() < 400) {
                    return new HttpsCheckResult("Habilitado", "valid", 10);
                } else {
                    return new HttpsCheckResult("Deshabilitado", "error", -30);
                }
            }
        } catch (Exception e) {
            return new HttpsCheckResult("Deshabilitado", "error", -30);
        }
    }

    private RedirectCheckResult checkHttpToHttpsRedirect(String url) {
        try {
            // Solo verificar si la URL original es HTTP
            if (url.startsWith("https://")) {
                return new RedirectCheckResult("No aplica (ya es HTTPS)", "valid", 0);
            }
            
            String httpUrl = url;
            if (!httpUrl.startsWith("http://")) {
                httpUrl = "http://" + httpUrl;
            }
            
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(httpUrl))
                .GET()
                .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            // Verificar si hay redirección a HTTPS (301, 302, 307, 308 con Location header https)
            int statusCode = response.statusCode();
            boolean isRedirect = statusCode >= 300 && statusCode < 400;
            
            if (isRedirect) {
                List<String> locationHeaders = response.headers().allValues("Location");
                boolean redirectsToHttps = locationHeaders.stream()
                    .anyMatch(loc -> loc.startsWith("https://"));
                
                if (redirectsToHttps) {
                    return new RedirectCheckResult("Activa", "valid", 15);
                } else {
                    return new RedirectCheckResult("Redirección sin HTTPS", "warning", -5);
                }
            } else if (statusCode >= 200 && statusCode < 300) {
                // Responde HTTP sin redireccionar - MAL
                return new RedirectCheckResult("Inactiva", "error", -25);
            } else {
                return new RedirectCheckResult("No verificable", "warning", 0);
            }
            
        } catch (Exception e) {
            return new RedirectCheckResult("No verificable", "warning", 0);
        }
    }

    private CompressionCheckResult checkGzipCompression(String url) {
        try {
            String targetUrl = url.startsWith("http") ? url : "https://" + url;
            
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
            
            // Request con Accept-Encoding para gzip
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("Accept-Encoding", "gzip, deflate")
                .GET()
                .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            List<String> contentEncoding = response.headers().allValues("Content-Encoding");
            boolean hasGzip = contentEncoding.stream()
                .anyMatch(enc -> enc.toLowerCase().contains("gzip"));
            
            if (hasGzip) {
                return new CompressionCheckResult("Habilitada", "valid", 5);
            } else {
                return new CompressionCheckResult("Deshabilitada", "warning", -10);
            }
            
        } catch (Exception e) {
            return new CompressionCheckResult("No verificable", "warning", 0);
        }
    }

    private DirectoryListingCheckResult checkDirectoryListing(String url) {
        try {
            String baseUrl = url.startsWith("http") ? url : "https://" + url;
            // Quitar trailing slash si existe
            baseUrl = baseUrl.replaceAll("/$", "");
            
            // Probar paths comunes que podrían tener listado de directorios
            String[] testPaths = {"/images/", "/css/", "/js/", "/assets/", "/uploads/"};
            
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
            
            for (String path : testPaths) {
                String testUrl = baseUrl + path;
                
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(testUrl))
                    .GET()
                    .build();
                
                try {
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    
                    if (response.statusCode() == 200) {
                        String body = response.body().toLowerCase();
                        
                        // Detectar patrones comunes de listado de directorios
                        boolean isDirectoryListing = 
                            body.contains("index of") ||
                            body.contains("directory listing") ||
                            body.contains("<title>index of ") ||
                            body.contains("parent directory") ||
                            (body.contains("<a href=") && body.contains("[dir]"));
                        
                        if (isDirectoryListing) {
                            return new DirectoryListingCheckResult("Habilitado", "error", -35);
                        }
                    }
                } catch (Exception e) {
                    // Continuar con el siguiente path
                }
            }
            
            // No se encontró listado de directorios en ningún path probado
            return new DirectoryListingCheckResult("Deshabilitado", "valid", 10);
            
        } catch (Exception e) {
            return new DirectoryListingCheckResult("No verificable", "warning", 0);
        }
    }

    // Records auxiliares
    private record HttpsCheckResult(String value, String status, int score) {}
    private record RedirectCheckResult(String value, String status, int score) {}
    private record CompressionCheckResult(String value, String status, int score) {}
    private record DirectoryListingCheckResult(String value, String status, int score) {}
}