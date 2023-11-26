package com.nzaeta.SecurityJWT.Repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nzaeta.SecurityJWT.Entity.User;


public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email); 
}
