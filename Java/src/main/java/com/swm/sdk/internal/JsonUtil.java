package com.swm.sdk.internal;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.swm.sdk.SwmException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class JsonUtil {
    public static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonUtil() {}

    public static JsonNode parse(byte[] bytes, String context) {
        try {
            return MAPPER.readTree(bytes);
        } catch (IOException exception) {
            throw new SwmException.Protocol(context + ": " + exception.getMessage());
        }
    }

    public static JsonNode parse(String text, String context) {
        return parse(text.getBytes(StandardCharsets.UTF_8), context);
    }

    public static byte[] bytes(JsonNode value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (IOException exception) {
            throw new SwmException.Protocol("cannot serialize JSON: " + exception.getMessage());
        }
    }

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    public static String text(JsonNode value, String field, boolean required) {
        var node = value == null ? null : value.get(field);
        if (node == null || node.isNull()) {
            if (required) {
                throw new SwmException.Protocol("missing JSON field: " + field);
            }
            return "";
        }
        if (!node.isTextual()) {
            throw new SwmException.Protocol("JSON field is not a string: " + field);
        }
        return node.asText();
    }

    public static String text(JsonNode value, String field) {
        return text(value, field, true);
    }

    public static long longValue(JsonNode value, String field, long fallback) {
        var node = value == null ? null : value.get(field);
        if (node == null || node.isNull()) {
            return fallback;
        }
        if (!node.isIntegralNumber()) {
            throw new SwmException.Protocol("JSON field is not an integer: " + field);
        }
        return node.longValue();
    }

    public static int intValue(JsonNode value, String field, int fallback) {
        var node = value == null ? null : value.get(field);
        if (node == null || node.isNull()) {
            return fallback;
        }
        if (!node.isIntegralNumber()) {
            throw new SwmException.Protocol("JSON field is not an integer: " + field);
        }
        return node.intValue();
    }

    public static boolean boolValue(JsonNode value, String field, boolean fallback) {
        var node = value == null ? null : value.get(field);
        if (node == null || node.isNull()) {
            return fallback;
        }
        if (!node.isBoolean()) {
            throw new SwmException.Protocol("JSON field is not a boolean: " + field);
        }
        return node.booleanValue();
    }

    /**
     * Returns the exact bytes of a top-level member value. Jackson is used only
     * to identify token boundaries; the hash is always calculated over the
     * original response slice.
     */
    public static byte[] rawMember(byte[] document, String member) {
        try (JsonParser parser = MAPPER.getFactory().createParser(new ByteArrayInputStream(document))) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) {
                    return null;
                }
                var name = parser.currentName();
                var valueToken = parser.nextToken();
                if (valueToken == null) {
                    return null;
                }
                var valueStart = valueStart(parser, document);
                if (valueStart < 0) {
                    return null;
                }
                var valueEnd = scanValueEnd(parser, document, valueStart);
                if (valueEnd < 0) {
                    return null;
                }
                if (member.equals(name)) {
                    var result = new byte[valueEnd - valueStart];
                    System.arraycopy(document, valueStart, result, 0, result.length);
                    return result;
                }
                if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
                    parser.skipChildren();
                }
            }
            return null;
        } catch (IOException exception) {
            throw new SwmException.Protocol("invalid JSON response");
        }
    }

    private static int valueStart(JsonParser parser, byte[] document) throws IOException {
        var location = parser.currentTokenLocation();
        if (location == null) {
            return -1;
        }
        var offset = (int) location.getByteOffset();
        while (offset < document.length &&
                (document[offset] == ' ' || document[offset] == '\t' ||
                    document[offset] == '\r' || document[offset] == '\n' || document[offset] == ':')) {
            offset++;
        }
        return offset;
    }

    private static int scanValueEnd(JsonParser parser, byte[] document, int start)
            throws IOException {
        var depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int index = start; index < document.length; index++) {
            var character = (char) (document[index] & 0xff);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (character == '\\') {
                    escaped = true;
                } else if (character == '"') {
                    inString = false;
                }
                continue;
            }
            if (character == '"') {
                inString = true;
            } else if (character == '{' || character == '[') {
                depth++;
            } else if (character == '}' || character == ']') {
                if (depth == 0) {
                    return trimEnd(document, index);
                }
                depth--;
                if (depth == 0) {
                    return index + 1;
                }
            } else if (depth == 0 && character == ',') {
                return trimEnd(document, index);
            }
        }
        return -1;
    }

    private static int trimEnd(byte[] document, int end) {
        while (end > 0) {
            var value = document[end - 1];
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                break;
            }
            end--;
        }
        return end;
    }
}
