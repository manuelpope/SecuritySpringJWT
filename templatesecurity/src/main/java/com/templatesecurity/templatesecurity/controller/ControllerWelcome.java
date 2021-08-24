package com.templatesecurity.templatesecurity.controller;

import com.templatesecurity.templatesecurity.websecurityjwt.service.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * The type Controller welcome.
 */
@RestController
public class ControllerWelcome {
    @Autowired
    private JWTUtil jwtUtil;

    /**
     * Hola string.
     *
     * @return the string
     */
    @GetMapping("/hola")
    @ResponseBody
    public String hola() {

        return "has hecho una peticion get";

    }

    /**
     * Holafresh string.
     *
     * @param request the request
     * @return the string
     */
    @GetMapping("/holafresh")
    @ResponseBody
    public String holafresh(HttpServletRequest request) {

        if (jwtUtil.isFresh(request)) {

            return "has hecho una peticion get hola fresh";

        }
        return "Not a fresh token to have full access must log in again";
    }


}
