package fixtures.c01;
public final class Provider {
  public static String value(boolean missing) { return missing ? null : "ok"; }
}
