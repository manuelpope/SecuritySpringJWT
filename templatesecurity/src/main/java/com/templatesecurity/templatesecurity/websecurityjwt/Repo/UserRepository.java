package com.templatesecurity.templatesecurity.websecurityjwt.Repo;

import com.templatesecurity.templatesecurity.websecurityjwt.Repo.model.DAOUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<DAOUser, Long> {


    DAOUser findByUsername(String username);

}