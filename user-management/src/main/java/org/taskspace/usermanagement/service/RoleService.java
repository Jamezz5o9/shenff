package org.taskspace.usermanagement.service;

import org.taskspace.usermanagement.data.models.Role;

public interface RoleService {

    Role createRole(String roleName);

    Role findUserRoleByName(String user);
}
