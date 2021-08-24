package com.templatesecurity.templatesecurity.websecurityjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;

import static com.templatesecurity.templatesecurity.websecurityjwt.config.filter.JwtFilterRequest.EXTRACT_JWT_FROM_REQUEST;


/**
 * The type Jwt util.
 */
@Component
public class JWTUtil {
    private static final String KEY = "pl4tz1";
    /**
     * The constant BACK_lIST.
     */
    protected static ArrayList<String> BACK_lIST = new ArrayList<>();
    private long refreshExpirationDateInMs = 3600 * 1000 * 7;
    private long tokenExpirationDateInMs = 3600 * 1000;

    /**
     * Generate token string.
     *
     * @param userDetails the user details
     * @return the string
     */
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpirationDateInMs))
                .signWith(SignatureAlgorithm.HS256, KEY).compact();
    }

    /**
     * Validate token boolean.
     *
     * @param token       the token
     * @param userDetails the user details
     * @return the boolean
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(extractUsername(token)) && !isTokenExpired(token) && !isInBlackList(token);
    }

    /**
     * Do generate refresh token string.
     *
     * @param userDetails the user details
     * @param jwt         the jwt
     * @return the string
     */
    public String doGenerateRefreshToken(UserDetails userDetails, String jwt) {

        return Jwts.builder().setClaims(getClaims(jwt).setAudience("-refresh")).setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
                .signWith(SignatureAlgorithm.HS512, KEY).compact();

    }

    /**
     * Extract username string.
     *
     * @param token the token
     * @return the string
     */
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * Is token expired boolean.
     *
     * @param token the token
     * @return the boolean
     */
    public boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    /**
     * Gets claims.
     *
     * @param token the token
     * @return the claims
     */
    public Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();
    }

    /**
     * Add back list jwt.
     *
     * @param jwt the jwt
     */
    public void addBackListJWT(String jwt) {
        BACK_lIST.add(jwt);

    }

    /**
     * Is in black list boolean.
     *
     * @param jwt the jwt
     * @return the boolean
     */
    public boolean isInBlackList(String jwt) {
        return BACK_lIST.contains(jwt);
    }

    /**
     * Is fresh boolean.
     *
     * @param request the request
     * @return the boolean
     */
    public boolean isFresh(HttpServletRequest request) {
        String jwt = EXTRACT_JWT_FROM_REQUEST.apply(request);
        return !getClaims(jwt).getAudience().endsWith("-refresh");


    }
}
