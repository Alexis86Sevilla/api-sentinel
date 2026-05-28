package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

@Service
public class SslInfoService {

    public SecurityAuditResult getSslInfo(String url) {
        List<SecurityItem> items = new ArrayList<>();
        int score = 100;
        
        try {
            String httpsUrl = url.startsWith("http://") 
                ? url.replace("http://", "https://")
                : (url.startsWith("https://") ? url : "https://" + url);
            
            URL parsedUrl = new URL(httpsUrl);
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort() == -1 ? 443 : parsedUrl.getPort();
            
            SSLContext sslContext = SSLContext.getDefault();
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.startHandshake();
                
                SSLSession session = socket.getSession();
                Certificate[] certs = session.getPeerCertificates();
                
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certs[0];
                    
                    // Certificate algorithm
                    String sigAlg = cert.getSigAlgName();
                    String algorithm = extractAlgorithm(sigAlg);
                    int certScore = calculateCertificateScore(algorithm);
                    score += certScore;
                    
                    items.add(new SecurityItem(
                        "certificate",
                        "Certificado SSL",
                        "Válido (" + algorithm + ")",
                        certScore >= 0 ? "valid" : "warning"
                    ));
                    
                    // TLS Protocol
                    String protocol = session.getProtocol();
                    String protocolVersion = protocol.replace("TLS", "TLS ").replace("  ", " ");
                    int protocolScore = calculateProtocolScore(protocol);
                    score += protocolScore;
                    boolean isModern = protocolScore >= 0;
                    
                    items.add(new SecurityItem(
                        "protocol",
                        "Protocolo TLS",
                        protocolVersion,
                        isModern ? "valid" : "warning"
                    ));
                    
                    // Expiration
                    Instant notAfter = cert.getNotAfter().toInstant();
                    Instant now = Instant.now();
                    long daysUntilExpiry = ChronoUnit.DAYS.between(now, notAfter);
                    int expiryScore = calculateExpirationScore(daysUntilExpiry);
                    score += expiryScore;
                    String expiryStatus = daysUntilExpiry > 30 ? "valid" 
                        : daysUntilExpiry > 7 ? "warning" 
                        : "invalid";
                    
                    items.add(new SecurityItem(
                        "expiration",
                        "Expiración",
                        daysUntilExpiry + " días",
                        expiryStatus
                    ));
                    
                    // Cipher Suite
                    String cipherSuite = session.getCipherSuite();
                    String cipher = extractCipherName(cipherSuite);
                    int cipherScore = calculateCipherScore(cipherSuite);
                    score += cipherScore;
                    boolean isStrong = cipherScore >= 0;
                    
                    items.add(new SecurityItem(
                        "cipher",
                        "Cifrado",
                        cipher,
                        isStrong ? "valid" : "warning"
                    ));
                }
            }
            
        } catch (Exception e) {
            score = 0;
            items.add(new SecurityItem(
                "certificate",
                "Certificado SSL",
                "Error: " + e.getMessage(),
                "error"
            ));
            items.add(new SecurityItem(
                "protocol",
                "Protocolo TLS",
                "No disponible",
                "error"
            ));
            items.add(new SecurityItem(
                "expiration",
                "Expiración",
                "No disponible",
                "error"
            ));
            items.add(new SecurityItem(
                "cipher",
                "Cifrado",
                "No disponible",
                "error"
            ));
        }
        
        score = Math.max(0, Math.min(100, score));
        return new SecurityAuditResult(score, items);
    }
    
    private String extractAlgorithm(String sigAlg) {
        if (sigAlg.contains("SHA256") || sigAlg.contains("SHA-256")) {
            return "SHA-256";
        } else if (sigAlg.contains("SHA384") || sigAlg.contains("SHA-384")) {
            return "SHA-384";
        } else if (sigAlg.contains("SHA512") || sigAlg.contains("SHA-512")) {
            return "SHA-512";
        } else if (sigAlg.contains("SHA1") || sigAlg.contains("SHA-1")) {
            return "SHA-1";
        } else {
            return sigAlg;
        }
    }
    
    private int calculateCertificateScore(String algorithm) {
        return switch (algorithm) {
            case "SHA-256" -> 0;
            case "SHA-384", "SHA-512" -> 5;
            case "SHA-1" -> -40;
            default -> -10;
        };
    }
    
    private int calculateProtocolScore(String protocol) {
        if (protocol.contains("1.3")) {
            return 10;
        } else if (protocol.contains("1.2")) {
            return 0;
        } else if (protocol.contains("1.1")) {
            return -30;
        } else if (protocol.contains("1.0") || protocol.contains("SSL")) {
            return -50;
        } else {
            return -20;
        }
    }
    
    private int calculateExpirationScore(long daysUntilExpiry) {
        if (daysUntilExpiry > 90) {
            return 5;
        } else if (daysUntilExpiry > 30) {
            return 0;
        } else if (daysUntilExpiry > 7) {
            return -20;
        } else if (daysUntilExpiry > 0) {
            return -40;
        } else {
            return -60;
        }
    }
    
    private int calculateCipherScore(String cipherSuite) {
        if (cipherSuite.contains("AES_256_GCM") || cipherSuite.contains("AES-256-GCM")) {
            return 5;
        } else if (cipherSuite.contains("CHACHA20")) {
            return 5;
        } else if (cipherSuite.contains("AES_128_GCM") || cipherSuite.contains("AES-128-GCM")) {
            return 0;
        } else if (cipherSuite.contains("AES_256") || cipherSuite.contains("AES-256")) {
            return 0;
        } else if (cipherSuite.contains("AES_128") || cipherSuite.contains("AES-128")) {
            return -10;
        } else if (cipherSuite.contains("RC4") || cipherSuite.contains("DES") || cipherSuite.contains("3DES")) {
            return -50;
        } else {
            return -15;
        }
    }
    
    private String extractCipherName(String cipherSuite) {
        if (cipherSuite.contains("AES_256_GCM") || cipherSuite.contains("AES-256-GCM")) {
            return "AES-256-GCM";
        } else if (cipherSuite.contains("AES_128_GCM") || cipherSuite.contains("AES-128-GCM")) {
            return "AES-128-GCM";
        } else if (cipherSuite.contains("AES_256") || cipherSuite.contains("AES-256")) {
            return "AES-256";
        } else if (cipherSuite.contains("AES_128") || cipherSuite.contains("AES-128")) {
            return "AES-128";
        } else if (cipherSuite.contains("CHACHA20")) {
            return "ChaCha20-Poly1305";
        } else {
            return cipherSuite;
        }
    }
}