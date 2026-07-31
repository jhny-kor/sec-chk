final class Fixture { String xml(HttpServletRequest request) { return "<user>" + request.getParameter("name"); } }
