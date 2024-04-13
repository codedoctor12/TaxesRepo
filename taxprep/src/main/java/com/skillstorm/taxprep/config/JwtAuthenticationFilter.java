package com.skillstorm.taxprep.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
//will be first class to intercept every call 
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;


    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
     @NonNull HttpServletRequest request,
     @NonNull HttpServletResponse response, 
     @NonNull FilterChain filterChain)

            throws ServletException, IOException {
                final String authHeader=request.getHeader("Authorization");
                final String jwt;
                final String userEmail;
                if(authHeader == null || !authHeader.startsWith("Bearer "))
                {
                  filterChain.doFilter(request, response);
                  return;
                }
                //grabing the bearer token excluding the 'Bearer '
                jwt = authHeader.substring(7);
                //grabbing extracting the User name from the token 
                userEmail = jwtService.extractUsername(jwt);
                //if we have a useremail but the user is not Authenticated 
                if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null)
                {
                    //get the details from the database
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                    /**checking if the user has a valid token if so
                     * We make provide a new authenticatication token and then
                     * put it in the request
                     * 
                    */
                    if(jwtService.isTokenValid(jwt, userDetails))
                    {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userEmail,
                            null, 
                            userDetails.getAuthorities());
                            authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                                
                            );
                            //updating security context holder
                            SecurityContextHolder.getContext().setAuthentication(authToken);

                    }
       
       
                }

                filterChain.doFilter(request, response);
    }




}
