package com.kki.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;

@Service
public class JwtService {

  //f713aec478269581492d82588865a6dfa2dbd66850d8bd76ff7aa248033d8b28
  // HEX : 66373133616563343738323639353831343932643832353838383635613664666132646264363638353064386264373666663761613234383033336438623238

  private static final String SECRET_KEY= "66373133616563343738323639353831343932643832353838383635613664666132646264363638353064386264373666663761613234383033336438623238";
  public String extractUsername(String jwtToken){
    return extractClaim(jwtToken, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String generateToken (UserDetails userDetails){
    return generateToken(new HashMap<>(), userDetails);
  }
  public String generateToken(Map<String, Object> extraClaims,
                              UserDetails userDetails ){
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public boolean isTokenValid (String token, UserDetails userDetails){
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokeExpired(token);
  }

  private boolean isTokeExpired (String token){
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token){
    return extractClaim(token, Claims::getExpiration);
  }

  private Claims extractAllClaims(String token){
    return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Key getSignInKey(){
      byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
      return Keys.hmacShaKeyFor(keyByte);
  }


}
