package org.taskspace.usermanagement.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.taskspace.usermanagement.data.models.Role;
import org.taskspace.usermanagement.data.repository.RoleRepository;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService{

    private final RoleRepository roleRepository;
    @Override
    public Role createRole(String roleName) {
        Role role = new Role();
        role.setName(roleName);
        return roleRepository.save(role);
    }

    @Override
    public Role findUserRoleByName(String role) {
        return roleRepository.findByName(role);
    }
}
