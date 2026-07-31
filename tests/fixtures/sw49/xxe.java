import javax.xml.parsers.DocumentBuilderFactory;
final class Fixture { void parse(java.io.InputStream input) throws Exception {
  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
  DocumentBuilder builder = factory.newDocumentBuilder();
  builder.parse(request.getInputStream());
} }
