package com.templatesecurity.templatesecurity.websecurityjwt.Repo.model;


import lombok.Data;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;

/**
 * The type Dao user.
 */
@Entity
@Table(name = "USER_SE")
@ToString
@Data
public class DAOUser implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Column(unique = true)
    private String username;
    @Column
    private String password;
    @Column
    private String role;


}