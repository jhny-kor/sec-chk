final class Fixture {
    @DeleteMapping("/admin/users/{id}")
    public void deleteUser(String id) {
        repository.delete(id);
    }
}
