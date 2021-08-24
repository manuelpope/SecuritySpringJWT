package com.templatesecurity.templatesecurity.websecurityjwt.Repo;

import com.templatesecurity.templatesecurity.websecurityjwt.Repo.model.DAOUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * The interface User repository.
 */
@Repository
public interface UserRepository extends JpaRepository<DAOUser, Long> {


    /**
     * Find by username dao user.
     *
     * @param username the username
     * @return the dao user
     */
    DAOUser findByUsername(String username);

}