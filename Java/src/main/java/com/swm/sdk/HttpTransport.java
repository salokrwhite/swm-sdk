package com.swm.sdk;

import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Injectable HTTP transport used by the SDK and test hosts.
 */
public interface HttpTransport {
    Response send(Request request, Duration timeout);
    StreamResponse stream(Request request, Duration timeout);

    record Request(
        String method,
        URI uri,
        Map<String, List<String>> headers,
        byte[] body,
        Duration timeout
    ) {}

    record Response(int statusCode, Map<String, List<String>> headers, byte[] body) {}

    record StreamResponse(
        int statusCode,
        Map<String, List<String>> headers,
        InputStream body
    ) implements AutoCloseable {
        @Override
        public void close() {
            try {
                body.close();
            } catch (Exception ignored) {
                // Best effort.
            }
        }
    }
}
