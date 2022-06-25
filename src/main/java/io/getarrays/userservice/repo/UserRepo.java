package io.getarrays.userservice.repo;

import io.getarrays.userservice.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author Get Arrays (https://www.getarrays.io/)
 * @version 1.0
 * @since 7/10/2021
 */
@Repository
public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
