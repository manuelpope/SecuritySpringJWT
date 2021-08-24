package com.templatesecurity.templatesecurity.websecurityjwt.dto;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class AuthenticationRequest {

    @NotBlank(message = "could not be blank field name")
    private String username;

    @NotBlank(message = "could not be blank field name")
    private String password;


}
