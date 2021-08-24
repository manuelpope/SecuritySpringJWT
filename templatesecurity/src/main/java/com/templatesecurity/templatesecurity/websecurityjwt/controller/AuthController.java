package com.templatesecurity.templatesecurity.websecurityjwt.controller;


import com.templatesecurity.templatesecurity.websecurityjwt.dto.AuthenticationRequest;
import com.templatesecurity.templatesecurity.websecurityjwt.dto.AuthenticationResponse;
import com.templatesecurity.templatesecurity.websecurityjwt.dto.UserDTO;
import com.templatesecurity.templatesecurity.websecurityjwt.service.DetailUserService;
import com.templatesecurity.templatesecurity.websecurityjwt.service.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpServerErrorException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private DetailUserService detailUserService;

    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping("/authenticate")
    public ResponseEntity<Map> createToken(@Valid @RequestBody AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            UserDetails userDetails = detailUserService.loadUserByUsername(request.getUsername());
            String jwt = jwtUtil.generateToken(userDetails);
            Map<String, Object> response = new HashMap<>();
            response.put("token", new AuthenticationResponse(jwt));
            response.put("userName", request.getUsername());
            response.put("role", userDetails.getAuthorities());


            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", e.getMessage());

            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }


    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> saveUser(@Valid @RequestBody UserDTO user) throws Exception {
        try {
            return ResponseEntity.ok(detailUserService.save(user));
        } catch (Exception ex) {

        }
        return new ResponseEntity<>("Not valid username", HttpStatus.INTERNAL_SERVER_ERROR);

    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult()
                .getAllErrors()
                .forEach(
                        (error) -> {
                            String fieldName = ((FieldError) error).getField();
                            String errorMessage = error.getDefaultMessage();
                            errors.put(fieldName, errorMessage);
                        });
        return errors;
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(HttpServerErrorException.InternalServerError.class)
    public Map<String, String> handleInternalExceptions(Exception ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return errors;
    }

    @RequestMapping(value = "/refreshtoken", method = RequestMethod.POST)
    public ResponseEntity<?> refreshToken(HttpServletRequest request) throws Exception {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
            String jwt = authorizationHeader.substring(7);
            String username = jwtUtil.extractUsername(jwt);
            UserDetails userDetails = detailUserService.loadUserByUsername(username);


            return ResponseEntity.ok(jwtUtil.doGenerateRefreshToken(userDetails, jwt));
        }

        return new ResponseEntity<>("No a valid Token", HttpStatus.FORBIDDEN);
    }

    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity<?> logout(HttpServletRequest request) throws Exception {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
            String jwt = authorizationHeader.substring(7);
            jwtUtil.addBackListJWT(jwt);


            return ResponseEntity.ok("successful logged out");
        }

        return new ResponseEntity<>("No a valid Token", HttpStatus.BAD_REQUEST);
    }


}
