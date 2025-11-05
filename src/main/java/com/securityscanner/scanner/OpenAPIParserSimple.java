package com.team184.scanner;

import java.net.*;
import java.io.*;
import java.net.URLEncoder;

public class OpenAPIParserSimple {
    
    private static final String BASE_URL = "https://vbank.open.bankingapi.ru";
    
    public static void main(String[] args) {
        System.out.println("🚀 Starting Simple OpenAPI Parser...");
        
        try {
            String openApiSpec = getOpenAPISpecification();
            
            if (openApiSpec != null) {
                System.out.println("✅ Successfully retrieved OpenAPI specification");
                System.out.println("📊 Specification length: " + openApiSpec.length() + " characters");
                
                // Простой анализ без JSON парсера
                simpleAnalysis(openApiSpec);
                
                // Сохраним для ручного анализа
                saveSpecToFile(openApiSpec, "vbank_openapi_simple.json");
            } else {
                System.out.println("❌ Could not find OpenAPI specification");
            }
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String getOpenAPISpecification() throws Exception {
        System.out.println("🔍 Searching for OpenAPI specification...");
        
        String[] openApiPaths = {
            "/openapi.json",
            "/swagger.json", 
            "/v3/api-docs",
            "/api-docs",
            "/docs/swagger.json",
            "/swagger/v1/swagger.json"
        };
        
        for (String path : openApiPaths) {
            System.out.println("Trying: " + BASE_URL + path);
            String spec = tryGetOpenAPI(path);
            if (spec != null && !spec.isEmpty() && spec.contains("openapi") && spec.contains("paths")) {
                System.out.println("✅ Found valid OpenAPI at: " + path);
                return spec;
            }
        }
        
        return null;
    }
    
    private static String tryGetOpenAPI(String path) {
        try {
            URL url = new URL(BASE_URL + path);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                StringBuilder response = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(connection.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        response.append(line);
                    }
                }
                return response.toString();
            }
        } catch (Exception e) {
            // Continue to next path
        }
        return null;
    }
    
    private static void simpleAnalysis(String openApiJson) {
        System.out.println("\n=== SIMPLE OPENAPI ANALYSIS ===");
        
        // Поиск базовой информации
        if (openApiJson.contains("\"title\"")) {
            int titleStart = openApiJson.indexOf("\"title\":") + 8;
            int titleEnd = openApiJson.indexOf("\"", titleStart);
            String title = openApiJson.substring(titleStart, titleEnd);
            System.out.println("📋 API Title: " + title);
        }
        
        if (openApiJson.contains("\"version\"")) {
            int versionStart = openApiJson.indexOf("\"version\":") + 10;
            int versionEnd = openApiJson.indexOf("\"", versionStart);
            String version = openApiJson.substring(versionStart, versionEnd);
            System.out.println("🔢 API Version: " + version);
        }
        
        // Подсчет эндпоинтов
        int pathCount = countOccurrences(openApiJson, "\"/");
        System.out.println("📊 Estimated endpoints: " + pathCount);
        
        // Поиск методов
        String[] methods = {"\"get\"", "\"post\"", "\"put\"", "\"delete\"", "\"patch\""};
        for (String method : methods) {
            int count = countOccurrences(openApiJson, method);
            if (count > 0) {
                System.out.println("   " + method.toUpperCase() + " methods: " + count);
            }
        }
        
        // Поиск security schemes
        if (openApiJson.contains("securitySchemes")) {
            System.out.println("🔐 Security schemes defined");
        }
        
        // Поиск компонентов
        if (openApiJson.contains("\"components\"")) {
            System.out.println("🏗️ Components section found");
        }
    }
    
    private static int countOccurrences(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }
    
    private static void saveSpecToFile(String spec, String filename) {
        try {
            File file = new File(filename);
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(spec);
            }
            System.out.println("💾 Saved to: " + file.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("❌ Could not save file: " + e.getMessage());
        }
    }
}