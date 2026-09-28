package com.swm.sdk.internal;

import com.swm.sdk.SwmException;
import com.swm.sdk.SwmModels;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public final class Multipart {
    private static final int MAX_TOTAL = 32 * 1024 * 1024;
    private static final long MAX_ATTACHMENT = 5L * 1024 * 1024;

    private Multipart() {}

    public static Payload feedback(String deviceId, String channel, String defaultVersion,
                                   SwmModels.FeedbackRequest request) {
        if (request.content() == null || request.content().isBlank()) {
            throw new SwmException.Configuration("feedback content is required");
        }
        if (request.rating() != null && (request.rating() < 1 || request.rating() > 5)) {
            throw new SwmException.Configuration("feedback rating must be between 1 and 5");
        }
        if (request.metadata() != null && !request.metadata().isObject()) {
            throw new SwmException.Configuration("feedback metadata must be a JSON object");
        }
        var attachments = new ArrayList<java.nio.file.Path>();
        for (var path : request.attachments()) {
            if (path != null && !path.toString().isBlank()) {
                attachments.add(path);
            }
        }
        if (attachments.size() > 3) {
            throw new SwmException.Configuration("feedback supports at most 3 attachments");
        }
        var boundary = "----------------------------" + CryptoUtil.hex(CryptoUtil.randomBytes(12));
        try {
            var output = new ByteArrayOutputStream();
            field(output, boundary, "device_id", deviceId);
            field(output, boundary, "channel_code", channel);
            field(output, boundary, "content", request.content());
            if (request.rating() != null) {
                field(output, boundary, "rating", request.rating().toString());
            }
            field(output, boundary, "contact", request.contact());
            field(output, boundary, "app_version",
                request.appVersion() == null || request.appVersion().isBlank()
                    ? defaultVersion : request.appVersion());
            if (request.metadata() != null && request.metadata().size() > 0) {
                field(output, boundary, "metadata", request.metadata().toString());
            }
            for (var path : attachments) {
                if (!Files.isRegularFile(path)) {
                    throw new SwmException.Configuration("feedback attachment was not found");
                }
                var size = Files.size(path);
                if (size > MAX_ATTACHMENT) {
                    throw new SwmException.Configuration("feedback attachment exceeds 5 MiB");
                }
                output.write(("--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"attachments\"; filename=\""
                    + escape(path.getFileName().toString()) + "\"\r\n"
                    + "Content-Type: application/octet-stream\r\n\r\n")
                    .getBytes(StandardCharsets.UTF_8));
                Files.copy(path, output);
                output.write("\r\n".getBytes(StandardCharsets.UTF_8));
            }
            output.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
            if (output.size() > MAX_TOTAL) {
                throw new SwmException.Configuration("feedback payload exceeds 32 MiB");
            }
            return new Payload(output.toByteArray(),
                "multipart/form-data; boundary=" + boundary);
        } catch (IOException exception) {
            throw new SwmException.Configuration("cannot build feedback payload");
        }
    }

    private static void field(ByteArrayOutputStream output, String boundary, String name,
                              String value) throws IOException {
        if (value == null || value.isBlank()) {
            return;
        }
        output.write(("--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"" + escape(name) + "\"\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8));
        output.write(value.getBytes(StandardCharsets.UTF_8));
        output.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static String escape(String value) {
        return value.replace("\"", "%22").replace("\r", "").replace("\n", "");
    }

    public record Payload(byte[] body, String contentType) {}
}
