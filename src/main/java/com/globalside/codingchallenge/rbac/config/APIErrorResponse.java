package com.globalside.codingchallenge.rbac.config;

/**
 * Uniform error body for security level responses (401 and 403).
 */
public record APIErrorResponse(int status, String error, String message) {
}