package org.taskspace.gateway.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.taskspace.usermanagement.data.models.Role;
import org.taskspace.usermanagement.data.repository.RoleRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class InitializerService {
    private final RoleRepository roleRepository;

    @PostConstruct
    public void saveAdmin(){
        if (roleRepository.findAll().size() == 0)buildRoles();
    }

    private void buildRoles() {
        Role adminRole = new Role();
        adminRole.setName("ADMIN");
        Role userRole = new Role();
        userRole.setName("USER");
        roleRepository.saveAll(List.of(adminRole, userRole));
    }
}
