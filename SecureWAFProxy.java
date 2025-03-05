// Arquivo: OdinSecureWAFProxy.java

package com.odin.wafproxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CommonsRequestLoggingFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.regex.Pattern;

@SpringBootApplication
public class WafProxyApplication {
    public static void main(String[] args) {
        SpringApplication.run(WafProxyApplication.class, args);
    }

    @Bean
    public CommonsRequestLoggingFilter requestLoggingFilter() {
        CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
        loggingFilter.setIncludeClientInfo(true);
        loggingFilter.setIncludeQueryString(true);
        loggingFilter.setIncludePayload(true);
        loggingFilter.setIncludeHeaders(true);
        return loggingFilter;
    }

    @Bean
    public SecurityFilter securityFilter() {
        return new SecurityFilter();
    }
}

class SecurityFilter extends OncePerRequestFilter {
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(".*(\b(select|insert|update|delete|union|drop|--)\b).*", Pattern.CASE_INSENSITIVE);
    private static final Pattern XSS_PATTERN = Pattern.compile(".*(<script>).*", Pattern.CASE_INSENSITIVE);

    @Override
    protected void doFilterInternal(HttpServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String queryString = request.getQueryString();
        if (queryString != null && (SQL_INJECTION_PATTERN.matcher(queryString).matches() || XSS_PATTERN.matcher(queryString).matches())) {
            throw new ServletException("Request blocked by WAF");
        }
        filterChain.doFilter(request, response);
    }
}

@RestController
@RequestMapping("/proxy")
class ReverseProxyController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchFromBackend(@RequestParam String url) {
        if (!url.startsWith("http")) {
            return ResponseEntity.badRequest().body("Invalid URL");
        }
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.USER_AGENT, "Secure Proxy");
        return restTemplate.exchange(url, HttpMethod.GET, null, String.class);
    }
}

// Configuração de logging centralizado (ELK/Grafana)
@Bean
public CommonsRequestLoggingFilter centralizedLoggingFilter() {
    CommonsRequestLoggingFilter filter = new CommonsRequestLoggingFilter();
    filter.setIncludeHeaders(true);
    filter.setIncludeQueryString(true);
    return filter;
}

// Testes unitários e de integração devem ser implementados na pasta src/test/java
// utilizando frameworks como JUnit e Mockito
