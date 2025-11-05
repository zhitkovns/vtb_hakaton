package com.team184.scanner;

import java.net.*;
import java.io.*;
import java.net.URLEncoder;

public class BankingAPIScanner {
    
    private static final String AUTH_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
    private static final String API_BASE_URL = "https://api.bankingapi.ru";
    private static final String CLIENT_ID = "team184";
    private static final String CLIENT_SECRET = "EdJ457cTlEq6svh7BOB6rPML1BcMvjQI";
    
    public static void main(String[] args) {
        System.out.println("🚀 Starting Banking API Security Scanner...");
        
        try {
            // 1. Получаем access token
            String accessToken = getAccessToken();
            System.out.println("✅ Access Token received: " + accessToken.substring(0, Math.min(20, accessToken.length())) + "...");
            
            // 2. Тестируем API endpoints
            testAPIEndpoints(accessToken);
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String getAccessToken() throws Exception {
        System.out.println("🔑 Requesting access token...");
        
        String formData = "grant_type=client_credentials" +
                         "&client_id=" + URLEncoder.encode(CLIENT_ID, "UTF-8") +
                         "&client_secret=" + URLEncoder.encode(CLIENT_SECRET, "UTF-8");
        
        URL url = new URL(AUTH_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setDoOutput(true);
        
        // Send form data
        try (OutputStream os = connection.getOutputStream()) {
            os.write(formData.getBytes("UTF-8"));
        }
        
        int responseCode = connection.getResponseCode();
        System.out.println("📡 Auth response status: " + responseCode);
        
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        
        System.out.println("📡 Auth response body: " + response.toString());
        
        if (responseCode != 200) {
            throw new Exception("Failed to get token: " + responseCode + " - " + response.toString());
        }
        
        // Parse access token from JSON response
        String body = response.toString();
        if (body.contains("\"access_token\":")) {
            int tokenStart = body.indexOf("\"access_token\":\"") + 16;
            int tokenEnd = body.indexOf("\"", tokenStart);
            return body.substring(tokenStart, tokenEnd);
        } else {
            throw new Exception("No access_token in response: " + body);
        }
    }
    
    private static void testAPIEndpoints(String accessToken) throws Exception {
        System.out.println("\n=== Testing Banking API Endpoints ===");
        
        // Common banking API endpoints
        String[] endpoints = {
            "/v1/accounts",
            "/v1/accounts/123",
            "/v1/balances", 
            "/v1/transactions",
            "/v1/customers/current",
            "/v1/consents",
            "/v1/payments",
            "/open-banking/v3.1/aisp/accounts",
            "/open-banking/v3.1/aisp/balances",
            "/open-banking/v3.1/aisp/transactions"
        };
        
        for (String endpoint : endpoints) {
            testEndpoint(accessToken, endpoint);
        }
        
        // Test security vulnerabilities
        testSecurityVulnerabilities(accessToken);
    }
    
    private static void testEndpoint(String accessToken, String endpoint) throws Exception {
        try {
            URL url = new URL(API_BASE_URL + endpoint);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            int responseCode = connection.getResponseCode();
            String responseBody = readResponse(connection, responseCode);
            
            analyzeEndpointResponse(endpoint, responseCode, responseBody);
            
        } catch (Exception e) {
            System.out.println("❌ " + endpoint + " -> Error: " + e.getClass().getSimpleName());
        }
    }
    
    private static void analyzeEndpointResponse(String endpoint, int responseCode, String responseBody) {
        String shortResponse = responseBody.length() > 100 ? responseBody.substring(0, 100) + "..." : responseBody;
        
        switch (responseCode) {
            case 200:
                System.out.println("✅ " + endpoint + " -> 200 OK");
                checkForVulnerabilities(endpoint, responseBody);
                break;
            case 201:
                System.out.println("✅ " + endpoint + " -> 201 Created");
                break;
            case 400:
                System.out.println("📋 " + endpoint + " -> 400 Bad Request");
                break;
            case 401:
                System.out.println("🔐 " + endpoint + " -> 401 Unauthorized");
                break;
            case 403:
                System.out.println("🚫 " + endpoint + " -> 403 Forbidden");
                break;
            case 404:
                System.out.println("❓ " + endpoint + " -> 404 Not Found");
                break;
            case 500:
                System.out.println("💥 " + endpoint + " -> 500 Server Error");
                break;
            default:
                System.out.println("📡 " + endpoint + " -> " + responseCode);
        }
        
        if (responseCode != 404 && responseCode != 500) {
            System.out.println("   Response: " + shortResponse);
        }
    }
    
    private static void checkForVulnerabilities(String endpoint, String responseBody) {
        // Check for sensitive data exposure
        String[] sensitivePatterns = {
            "password", "secret", "private_key", "cvv", "ssn", 
            "passport", "birth_date", "mother_maiden"
        };
        
        for (String pattern : sensitivePatterns) {
            if (responseBody.toLowerCase().contains(pattern)) {
                System.out.println("   🚨 SENSITIVE DATA: " + pattern);
            }
        }
        
        // Check for excessive data
        if (responseBody.length() > 10000) {
            System.out.println("   ⚠️  LARGE RESPONSE: " + responseBody.length() + " chars");
        }
    }
    
    private static void testSecurityVulnerabilities(String accessToken) throws Exception {
        System.out.println("\n=== Testing Security Vulnerabilities ===");
        
        // Test IDOR/BOLA
        testIDOR(accessToken);
        
        // Test authentication bypass
        testAuthBypass();
        
        // Test information disclosure
        testInfoDisclosure(accessToken);
    }
    
    private static void testIDOR(String accessToken) throws Exception {
        System.out.println("Testing IDOR/BOLA vulnerabilities...");
        
        String[] testIds = {"1", "123", "me", "current", "admin", "0"};
        
        for (String id : testIds) {
            String endpoint = "/v1/accounts/" + id;
            testBOLA(accessToken, endpoint, id);
        }
    }
    
    private static void testBOLA(String accessToken, String endpoint, String resourceId) throws Exception {
        try {
            // Make request
            String response = makeAPIRequest(accessToken, endpoint);
            
            if (response.contains("Status: 200")) {
                System.out.println("   🔍 " + endpoint + " -> Accessible");
                // Here we would compare with other user's access
            }
        } catch (Exception e) {
            // Endpoint might not exist
        }
    }
    
    private static void testAuthBypass() throws Exception {
        System.out.println("Testing authentication bypass...");
        
        String[] endpoints = {"/", "/health", "/status", "/metrics"};
        
        for (String endpoint : endpoints) {
            try {
                URL url = new URL(API_BASE_URL + endpoint);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                
                int responseCode = connection.getResponseCode();
                if (responseCode == 200) {
                    System.out.println("   🚨 AUTH BYPASS: " + endpoint + " accessible without token");
                }
            } catch (Exception e) {
                // Continue
            }
        }
    }
    
    private static void testInfoDisclosure(String accessToken) throws Exception {
        System.out.println("Testing information disclosure...");
        
        String[] debugEndpoints = {
            "/debug", "/_debug", "/test", "/_test", 
            "/admin", "/_admin", "/.git", "/.env"
        };
        
        for (String endpoint : debugEndpoints) {
            testEndpoint(accessToken, endpoint);
        }
    }
    
    private static String makeAPIRequest(String accessToken, String endpoint) throws Exception {
        URL url = new URL(API_BASE_URL + endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);
        connection.setRequestProperty("Content-Type", "application/json");
        
        int responseCode = connection.getResponseCode();
        return "Status: " + responseCode + " | " + readResponse(connection, responseCode);
    }
    
    private static String readResponse(HttpURLConnection connection, int responseCode) throws Exception {
        StringBuilder response = new StringBuilder();
        InputStream inputStream = (responseCode >= 400) ? connection.getErrorStream() : connection.getInputStream();
        
        if (inputStream != null) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
            }
        }
        
        return response.toString();
    }
}