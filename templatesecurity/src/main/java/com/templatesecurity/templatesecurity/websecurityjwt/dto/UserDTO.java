package com.templatesecurity.templatesecurity.websecurityjwt.dto;


import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotEmpty;

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