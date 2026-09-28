package com.swm.sdk.internal;

import com.swm.sdk.HttpTransport;
import com.swm.sdk.SwmException;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public final class JdkHttpTransport implements HttpTransport {
    private final HttpClient client;

    public JdkHttpTransport(Duration connectTimeout) {
        this.client = HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    @Override
    public Response send(Request request, Duration timeout) {
        try {
            var response = client.send(toRequest(request),
                HttpResponse.BodyHandlers.ofByteArray());
            return new Response(response.statusCode(), response.headers().map(), response.body());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new SwmException.Timeout("HTTP request interrupted");
        } catch (IOException exception) {
            throw new SwmException.Network("HTTP request failed", exception);
        }
    }

    @Override
    public StreamResponse stream(Request request, Duration timeout) {
        try {
            var response = client.send(toRequest(request),
                HttpResponse.BodyHandlers.ofInputStream());
            return new StreamResponse(response.statusCode(), response.headers().map(),
                response.body());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new SwmException.Timeout("HTTP stream interrupted");
        } catch (IOException exception) {
            throw new SwmException.Network("HTTP stream failed", exception);
        }
    }

    private static HttpRequest toRequest(Request request) {
        var builder = HttpRequest.newBuilder(request.uri())
            .timeout(request.timeout())
            .method(request.method(), request.body() == null || request.body().length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(request.body()));
        request.headers().forEach((name, values) -> values.forEach(
            value -> builder.header(name, value)));
        return builder.build();
    }
}
