package securityscanner.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import securityscanner.core.model.Finding;
import securityscanner.parser.OpenAPIParserSimple;

import java.util.List;

public class ExecutionContext {
    public final String baseUrl;
    public final String accessToken;
    public final String requestingBank;
    public final String interbankClientId; // client_id вида teamXXX-1, если задан
    public final String consentId;         // consent-id, если создан
    public final boolean verbose;

    public final OkHttpClient http;
    public final ObjectMapper om;
    public final OpenAPIParserSimple parser;
    public final JsonNode openapiRoot;

    public final List<Finding> findings;

    public ExecutionContext(String baseUrl,
                            String accessToken,
                            String requestingBank,
                            String interbankClientId,
                            String consentId,
                            boolean verbose,
                            OkHttpClient http,
                            ObjectMapper om,
                            OpenAPIParserSimple parser,
                            JsonNode openapiRoot,
                            List<Finding> findings) {
        this.baseUrl = baseUrl;
        this.accessToken = accessToken;
        this.requestingBank = requestingBank;
        this.interbankClientId = interbankClientId;
        this.consentId = consentId;
        this.verbose = verbose;
        this.http = http;
        this.om = om;
        this.parser = parser;
        this.openapiRoot = openapiRoot;
        this.findings = findings;
    }
}
