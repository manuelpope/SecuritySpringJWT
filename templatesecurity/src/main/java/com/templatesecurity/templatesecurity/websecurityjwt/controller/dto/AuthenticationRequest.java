package com.templatesecurity.templatesecurity.websecurityjwt.controller.dto;

import lombok.Data;

import javax.validation.constraints.NotBlank;

/**
 * The type Authentication request.
 */
@Data
public class AuthenticationRequest {

    @NotBlank(message = "could not be blank field name")
    private String username;

    @NotBlank(message = "could not be blank field name")
    private String password;


}
