final class Fixture { void read() throws Exception {
  java.sql.Connection connection = DriverManager.getConnection(url);
  connection.prepareStatement("SELECT 1");
} }
