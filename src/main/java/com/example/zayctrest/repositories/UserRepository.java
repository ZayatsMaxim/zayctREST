package com.example.zayctrest.repositories;

import com.example.zayctrest.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> getUserById(Integer id);
    Optional<User> getUserByUsername(String username);
}