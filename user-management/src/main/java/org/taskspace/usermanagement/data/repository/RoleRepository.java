package org.taskspace.usermanagement.data.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.taskspace.usermanagement.data.models.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String role);
}
