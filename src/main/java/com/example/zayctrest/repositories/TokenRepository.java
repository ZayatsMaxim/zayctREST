package com.example.zayctrest.repositories;

import com.example.zayctrest.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query(
            value = "SELECT t FROM Token t INNER JOIN User u ON u.id = t.user.id " +
                    "WHERE u.id = :userId AND (t.expired = false or t.revoked = false)"
    )
    List<Token> findAllValidTokensByUser(Integer userId);

    Optional<Token> findByToken(String token);
}