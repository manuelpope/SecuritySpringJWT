package com.templatesecurity.templatesecurity.websecurityjwt.service;

import com.templatesecurity.templatesecurity.websecurityjwt.Repo.UserRepository;
import com.templatesecurity.templatesecurity.websecurityjwt.Repo.model.DAOUser;
import com.templatesecurity.templatesecurity.websecurityjwt.controller.dto.UserDTO;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;


/**
 * The type Detail user service.
 */
@Service
public class DetailUserService implements UserDetailsService {


    @Autowired
    private UserRepository userDao;

    @Autowired
    private PasswordEncoder bcryptEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles = null;

        DAOUser user = userDao.findByUsername(username);
        System.out.println(user.toString());

        if (Strings.isNotEmpty(user.getUsername())) {

            roles = Arrays.asList(new SimpleGrantedAuthority(user.getRole()));
            return new User(user.getUsername(), user.getPassword(),
                    roles);

        }
        throw new UsernameNotFoundException("not valid username ");
    }

    /**
     * Save dao user.
     *
     * @param user the user
     * @return the dao user
     * @throws Exception the exception
     */
    public DAOUser save(UserDTO user) throws Exception {

        DAOUser newUser = new DAOUser();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setRole(user.getRole());
        return userDao.save(newUser);
    }


}
