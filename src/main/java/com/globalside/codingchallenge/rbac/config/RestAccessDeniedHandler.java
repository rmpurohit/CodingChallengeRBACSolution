package com.globalside.codingchallenge.rbac.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

/**
 * Handles authorization failures for authenticated users.
 *
 * Returns HTTP 403 Forbidden with a JSON response when a user is
 * authenticated but does not have the required role or permission
 * to access a resource.
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"status\": 403, \"error\": \"Forbidden\", " +
                        "\"message\": \"You do not have permission to perform this action.\"}");
    }
}