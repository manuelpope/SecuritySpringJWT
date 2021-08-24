package com.templatesecurity.templatesecurity.websecurityjwt.security.filter;

import com.templatesecurity.templatesecurity.websecurityjwt.service.DetailUserService;
import com.templatesecurity.templatesecurity.websecurityjwt.service.JWTUtil;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

@Component
@Setter
public class JwtFilterRequest extends OncePerRequestFilter {


    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private DetailUserService detailUserService;

    public static Predicate<String> VALID_TOKEN_FORMAT = authorizationHeader1 -> authorizationHeader1 != null && authorizationHeader1.startsWith("Bearer");
    public static Function<String,String> VALID_JWT = s-> Optional.ofNullable(s).filter(VALID_TOKEN_FORMAT).map(r->r.substring(7)).orElse("undefined");
    public static Function<HttpServletRequest,String> EXTRACT_JWT_FROM_REQUEST = s->Optional.ofNullable(s.getHeader("Authorization"))
            .map(r->VALID_JWT.apply(r)).orElse("undefined");




    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
            String jwt = authorizationHeader.substring(7);
            String username = jwtUtil.extractUsername(jwt);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = detailUserService.loadUserByUsername(username);

                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
