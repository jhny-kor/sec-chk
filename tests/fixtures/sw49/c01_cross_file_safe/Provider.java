package fixtures.c01safe;
public final class Provider { public static String value(boolean missing) { return missing ? null : "ok"; } }
