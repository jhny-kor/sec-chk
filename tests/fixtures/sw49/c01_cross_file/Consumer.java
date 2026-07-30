package fixtures.c01;
public final class Consumer {
  public static int length(boolean missing) {
    return Provider.value(missing).length(); // CWE-476: cross-file source -> sink
  }
}
