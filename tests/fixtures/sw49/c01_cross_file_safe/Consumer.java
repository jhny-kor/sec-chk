package fixtures.c01safe;
public final class Consumer {
  public static int length(boolean missing) {
    String value = Provider.value(missing);
    return value == null ? 0 : value.length(); // guarded safe pair
  }
}
