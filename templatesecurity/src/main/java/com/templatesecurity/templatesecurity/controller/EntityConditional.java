package com.templatesecurity.templatesecurity.controller;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;


@Entity
@Table(name = "FOO_E")
@Data
public class EntityConditional implements Serializable {


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
