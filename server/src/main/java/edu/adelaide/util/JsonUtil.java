package edu.adelaide.util;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.io.StringReader;
import java.lang.reflect.Type;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Lightweight JSON utility built on Gson.
 * - Thread-safe static Gson instances.
 * - Object ⇄ JSON string / bytes / tree.
 * - Pretty & compact (minified) rendering.
 * - Lenient JSON validation.
 * - Generic Type helpers via TypeToken.
 * - Canonical JSON (sorted object keys) for signatures.
 *
 * Notes:
 * - Nulls are NOT serialized by default; use gsonSerializeNulls() if needed.
 * - java.time adapters serialize as ISO-8601 strings.
 */
public final class JsonUtil {

  // ---- Public entry points for most use-cases --------------------------------

  /** Default Gson (compact, no nulls, HTML escaping disabled). */
  public static Gson gson() { return Gsons.DEFAULT; }

  /** Pretty-printing Gson (includes newlines/indentation). */
  public static Gson gsonPretty() { return Gsons.PRETTY; }

  /** Gson that serializes nulls (compact). */
  public static Gson gsonSerializeNulls() { return Gsons.WITH_NULLS; }

  // --- Object → JSON ----------------------------------------------------------

  public static String toJson(Object value) {
    return gson().toJson(value);
  }

  public static String toJsonPretty(Object value) {
    return gsonPretty().toJson(value);
  }

  public static byte[] toJsonBytes(Object value) {
    return toJson(value).getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }

  public static JsonElement toTree(Object value) {
    return gson().toJsonTree(value);
  }

  // --- JSON → Object ----------------------------------------------------------

  public static <T> T fromJson(String json, Class<T> type) {
    Objects.requireNonNull(json, "json");
    Objects.requireNonNull(type, "type");
    return gson().fromJson(json, type);
  }

  public static <T> T fromJson(String json, Type type) {
    Objects.requireNonNull(json, "json");
    Objects.requireNonNull(type, "type");
    return gson().fromJson(json, type);
  }

  public static <T> T fromTree(JsonElement element, Class<T> type) {
    Objects.requireNonNull(element, "element");
    Objects.requireNonNull(type, "type");
    return gson().fromJson(element, type);
  }

  public static <T> Optional<T> tryFromJson(String json, Class<T> type) {
    try { return Optional.ofNullable(fromJson(json, type)); }
    catch (RuntimeException e) { return Optional.empty(); }
  }

  public static <T> Optional<T> tryFromJson(String json, Type type) {
    try { return Optional.ofNullable(fromJson(json, type)); }
    catch (RuntimeException e) { return Optional.empty(); }
  }

  // --- Validation / formatting helpers ---------------------------------------

  /** Returns true if the input is syntactically valid JSON (lenient allowed). */
  public static boolean isValidJson(String input) {
    if (input == null) return false;
    try (var reader = new com.google.gson.stream.JsonReader(new StringReader(input))) {
      reader.setLenient(true);
      JsonParser.parseReader(reader);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /** Minify (compact) an arbitrary JSON string (lenient parse). */
  public static String minify(String json) {
    var elem = parseLenient(json);
    return gson().toJson(elem);
  }

  /** Pretty-print an arbitrary JSON string (lenient parse). */
  public static String pretty(String json) {
    var elem = parseLenient(json);
    return gsonPretty().toJson(elem);
  }

  /** Parse JSON leniently to a JsonElement (comments, unquoted names tolerated). */
  public static JsonElement parseLenient(String json) {
    Objects.requireNonNull(json, "json");
    try (var reader = new com.google.gson.stream.JsonReader(new StringReader(json))) {
      reader.setLenient(true);
      return JsonParser.parseReader(reader);
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid JSON: " + e.getMessage(), e);
    }
  }

  // --- Canonical JSON (sorted object keys, compact) ---------------------------

  /**
   * Produce canonical JSON with lexicographically sorted keys (recursively).
   * Useful for deterministic signing / hashing.
   */
  public static String toCanonicalJson(JsonElement element) {
    JsonElement normalized = canonicalize(element);
    // compact rendering (no pretty-print; no HTML escaping)
    return Gsons.CANONICAL.toJson(normalized);
  }

  /** Canonicalize an element by sorting all object keys recursively. */
  public static JsonElement canonicalize(JsonElement element) {
    if (element == null || element.isJsonNull()) return JsonNull.INSTANCE;

    if (element.isJsonArray()) {
      JsonArray src = element.getAsJsonArray();
      JsonArray dst = new JsonArray();
      for (JsonElement e : src) dst.add(canonicalize(e));
      return dst;
    }

    if (element.isJsonObject()) {
      JsonObject src = element.getAsJsonObject();
      JsonObject dst = new JsonObject();
      // collect & sort keys
      List<String> keys = new ArrayList<>(src.keySet());
      Collections.sort(keys);
      for (String k : keys) {
        dst.add(k, canonicalize(src.get(k)));
      }
      return dst;
    }

    // primitives are already canonical
    return element.deepCopy();
  }

  /** Parse a JSON string and return its canonical compact JSON representation. */
  public static String toCanonicalJson(String json) {
    return toCanonicalJson(parseLenient(json));
  }

  // --- Generic Type helpers ---------------------------------------------------

  public static <T> Type listOf(Class<T> elementType) {
    return TypeToken.getParameterized(List.class, elementType).getType();
  }

  public static <K, V> Type mapOf(Class<K> keyType, Class<V> valType) {
    return TypeToken.getParameterized(Map.class, keyType, valType).getType();
  }

  public static <T> Type setOf(Class<T> elementType) {
    return TypeToken.getParameterized(Set.class, elementType).getType();
  }

  // ---- Internal: shared Gsons and adapters ----------------------------------

  private static final class Gsons {
    private static final Gson DEFAULT = baseBuilder(false, false).create();
    private static final Gson PRETTY  = baseBuilder(true,  false).create();
    private static final Gson WITH_NULLS = baseBuilder(false, true).create();
    private static final Gson CANONICAL = baseBuilder(false, false).create(); // same settings; tree is already sorted

    private static GsonBuilder baseBuilder(boolean pretty, boolean serializeNulls) {
      GsonBuilder b = new GsonBuilder()
          .disableHtmlEscaping()
          .registerTypeAdapter(Instant.class, new InstantAdapter())
          .registerTypeAdapter(OffsetDateTime.class, new OffsetDateTimeAdapter())
          .registerTypeAdapter(ZonedDateTime.class, new ZonedDateTimeAdapter());
      if (pretty) b.setPrettyPrinting();
      if (serializeNulls) b.serializeNulls();
      return b;
    }
  }

  // ISO-8601 time adapters (string <-> java.time.*)
  private static final class InstantAdapter implements JsonSerializer<Instant>, JsonDeserializer<Instant> {
    @Override public JsonElement serialize(Instant src, Type t, JsonSerializationContext c) {
      return new JsonPrimitive(src.toString()); // ISO-8601 UTC
    }
    @Override public Instant deserialize(JsonElement json, Type t, JsonDeserializationContext c)
        throws JsonParseException {
      return Instant.parse(json.getAsString());
    }
  }

  private static final class OffsetDateTimeAdapter implements JsonSerializer<OffsetDateTime>, JsonDeserializer<OffsetDateTime> {
    @Override public JsonElement serialize(OffsetDateTime src, Type t, JsonSerializationContext c) {
      return new JsonPrimitive(src.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
    }
    @Override public OffsetDateTime deserialize(JsonElement json, Type t, JsonDeserializationContext c)
        throws JsonParseException {
      return OffsetDateTime.parse(json.getAsString(), DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
  }

  private static final class ZonedDateTimeAdapter implements JsonSerializer<ZonedDateTime>, JsonDeserializer<ZonedDateTime> {
    @Override public JsonElement serialize(ZonedDateTime src, Type t, JsonSerializationContext c) {
      return new JsonPrimitive(src.format(DateTimeFormatter.ISO_ZONED_DATE_TIME));
    }
    @Override public ZonedDateTime deserialize(JsonElement json, Type t, JsonDeserializationContext c)
        throws JsonParseException {
      return ZonedDateTime.parse(json.getAsString(), DateTimeFormatter.ISO_ZONED_DATE_TIME);
    }
  }

  private JsonUtil() {}
}
