final class Fixture {
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/admin/users/{id}")
    public void deleteUser(String id) {
        repository.delete(id);
    }
}
