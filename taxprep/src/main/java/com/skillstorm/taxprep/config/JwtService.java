package com.skillstorm.taxprep.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String SECRET_KEY = "";
    ;
    public String extractUsername(String token)
    {
        return extractClaim(token, Claims::getSubject);

    }
    public String generateToken( Map<String,Object> extraClaims,
        UserDetails userDetail)
        {
            return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetail.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
        }
    public String generateToken(UserDetails userDetails)
    {
        return generateToken(new HashMap<>(),userDetails);
    }
    public boolean isTokenValid(String token, UserDetails userDetail)
    {
        final String username = extractUsername(token);
        return (username.equals(userDetail.getUsername()) && !isTokenExpired(token));
    }
    private boolean isTokenExpired(String token) {

       return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }
    public <T> T extractClaim(String token, Function<Claims,T> claimResolver)
    {
        final Claims  claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }
    private Claims extractAllClaims(String token)
    {
        return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();

    }
    private Key getSignInKey() {

      byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
      return Keys.hmacShaKeyFor(keyBytes);
    }
}
