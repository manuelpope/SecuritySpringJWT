package com.templatesecurity.templatesecurity.websecurityjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * The type Mapper functions.
 */

public class MapperFunctions {

    /**
     * The constant CLAIMS_EXTRACT_FUNCTION.
     */
    public static final BiFunction<String, String, Claims> CLAIMS_EXTRACT_FUNCTION = (token1, key) -> Jwts.parser().setSigningKey(key).parseClaimsJws(token1).getBody();
    /**
     * The constant IS_REFRESH_TOKEN.
     */
    public static final Predicate<String> IS_REFRESH_TOKEN = audience1 -> !audience1.endsWith("-refresh");
    /**
     * The Valid token format.
     */
    public static final Predicate<String> VALID_TOKEN_FORMAT = authorizationHeader1 -> authorizationHeader1 != null && authorizationHeader1.startsWith("Bearer");
    /**
     * The Valid jwt.
     */
    public static final Function<String, String> VALID_JWT = s -> Optional.ofNullable(s).filter(VALID_TOKEN_FORMAT).map(r -> r.substring(7)).orElse("undefined");
    /**
     * The Extract jwt from request.
     */
    public static final Function<HttpServletRequest, String> EXTRACT_JWT_FROM_REQUEST = s -> Optional.ofNullable(s.getHeader("Authorization")).map(r -> VALID_JWT.apply(r)).orElse(null);

}
