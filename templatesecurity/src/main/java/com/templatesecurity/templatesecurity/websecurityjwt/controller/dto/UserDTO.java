package com.templatesecurity.templatesecurity.websecurityjwt.controller.dto;


import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotEmpty;

/**
 * The type User dto.
 */
@Data
@AllArgsConstructor
public class UserDTO {
    @NotEmpty(message = "could not be blank field name")
    private String username;
    @NotEmpty(message = "could not be blank field name")
    private String password;
    @NotEmpty(message = "could not be blank field name")
    private String role;

}