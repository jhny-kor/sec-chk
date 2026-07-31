final class Fixture { void write(HttpServletResponse response, HttpServletRequest request) { response.setHeader("X-Name", request.getParameter("n")); } }
