package com.templatesecurity.templatesecurity.websecurityjwt.controller.dto;


import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * The type Authentication response.
 */
@Data
@AllArgsConstructor
public class AuthenticationResponse {
    private String jwt;

}
