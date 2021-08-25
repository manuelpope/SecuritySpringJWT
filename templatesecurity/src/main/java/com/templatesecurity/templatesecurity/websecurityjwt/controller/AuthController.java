package com.templatesecurity.templatesecurity.websecurityjwt.controller;


import com.templatesecurity.templatesecurity.websecurityjwt.controller.dto.AuthenticationRequest;
import com.templatesecurity.templatesecurity.websecurityjwt.controller.dto.AuthenticationResponse;
import com.templatesecurity.templatesecurity.websecurityjwt.controller.dto.UserDTO;
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

import static com.templatesecurity.templatesecurity.websecurityjwt.service.MapperFunctions.EXTRACT_JWT_FROM_REQUEST;

/**
 * The type Auth controller.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private DetailUserService detailUserService;

    @Autowired
    private JWTUtil jwtUtil;

    /**
     * Create token response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/authenticate")
    public ResponseEntity<Map> createToken(@Valid @RequestBody AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            UserDetails userDetails = detailUserService.loadUserByUsername(request.getUsername());
            String jwt = jwtUtil.generateToken(userDetails);
            String refreshToken = jwtUtil.doGenerateRefreshToken(userDetails, jwt);
            Map<String, Object> response = new HashMap<>();
            response.put("token", new AuthenticationResponse(jwt));
            response.put("userName", request.getUsername());
            response.put("role", userDetails.getAuthorities());
            response.put("refresh_token", refreshToken);


            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", e.getMessage());

            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }


    /**
     * Save user response entity.
     *
     * @param user the user
     * @return the response entity
     * @throws Exception the exception
     */
    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> saveUser(@Valid @RequestBody UserDTO user) throws Exception {
        try {
            return ResponseEntity.ok(detailUserService.save(user));
        } catch (Exception ex) {

        }
        return new ResponseEntity<>("Not valid username", HttpStatus.INTERNAL_SERVER_ERROR);

    }

    /**
     * Handle validation exceptions map.
     *
     * @param ex the ex
     * @return the map
     */
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

    /**
     * Handle internal exceptions map.
     *
     * @param ex the ex
     * @return the map
     */
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(HttpServerErrorException.InternalServerError.class)
    public Map<String, String> handleInternalExceptions(Exception ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return errors;
    }

    /**
     * Refresh token response entity.
     *
     * @param request the request
     * @return the response entity
     * @throws Exception the exception
     */
    @RequestMapping(value = "/refreshtoken", method = RequestMethod.POST)
    public ResponseEntity<?> refreshToken(HttpServletRequest request) throws Exception {

        String jwt = EXTRACT_JWT_FROM_REQUEST.apply(request);
        String username = jwtUtil.extractUsername(jwt);
        UserDetails userDetails = detailUserService.loadUserByUsername(username);
        String refreshToken = jwtUtil.doGenerateRefreshToken(userDetails, jwt);
        Map<String, Object> response = Map.of("refresh_token", refreshToken);

        return ResponseEntity.ok(response);


    }

    /**
     * Logout response entity.
     *
     * @param request the request
     * @return the response entity
     * @throws Exception the exception
     */
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity<?> logout(HttpServletRequest request) {

        String jwt = EXTRACT_JWT_FROM_REQUEST.apply(request);
        jwtUtil.addBackListJWT(jwt);


        return ResponseEntity.ok("successful logged out");


    }


}
