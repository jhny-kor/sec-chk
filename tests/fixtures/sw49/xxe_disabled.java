import javax.xml.parsers.DocumentBuilderFactory;
final class Fixture { void parse(java.io.InputStream input) throws Exception {
  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
  factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
  DocumentBuilder builder = factory.newDocumentBuilder();
  builder.parse(request.getInputStream());
} }
