package app.attestation.server;

import java.io.InputStream;
import java.io.OutputStream;

import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonBuilderFactory;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonReaderFactory;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;

class Json {
    private static final JsonReaderFactory readerFactory = jakarta.json.Json.createReaderFactory(null);
    private static final JsonWriterFactory writerFactory = jakarta.json.Json.createWriterFactory(null);
    private static final JsonBuilderFactory builderFactory = jakarta.json.Json.createBuilderFactory(null);

    static JsonReader createReader(final InputStream in) {
        return readerFactory.createReader(in);
    }

    static JsonWriter createWriter(final OutputStream out) {
        return writerFactory.createWriter(out);
    }

    static JsonArrayBuilder createArrayBuilder() {
        return builderFactory.createArrayBuilder();
    }

    static JsonObjectBuilder createObjectBuilder() {
        return builderFactory.createObjectBuilder();
    }
}
