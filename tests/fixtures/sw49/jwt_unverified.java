final class Fixture { Object parse(String token) { return jwt.decode(token, verify=false); } }
