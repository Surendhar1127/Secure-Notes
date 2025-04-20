package com.star.notes.Repository;

import com.star.notes.Model.AppRole;
import com.star.notes.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepo extends JpaRepository<Role, Long> {

     Optional<Role> findByRoleName(AppRole appRole);
}
