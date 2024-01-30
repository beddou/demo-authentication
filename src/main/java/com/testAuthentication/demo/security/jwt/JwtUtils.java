package com.testAuthentication.demo.security.jwt;

import java.security.Key;
import java.util.Collection;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.authority.AuthorityUtils;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${bezkoder.app.jwtSecret}")
  private String jwtSecret;

  @Value("${bezkoder.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  @Value("${bezkoder.app.jwtCookieName}")
  private String jwtCookie;

  public String getJwtFromCookies(HttpServletRequest request) {
    Cookie cookie = WebUtils.getCookie(request, jwtCookie);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }
  }

  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
    return cookie;
  }

  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }

  public Jws<Claims> getClaims(String authToken) {
    try {

      Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(authToken);
      return claims;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return null;
  }

  public String getUserNameFromJwtToken(String token) {
    Jws<Claims> jwsClaims = getClaims(token);
    if (jwsClaims == null) {
      return null;
    }

    Claims claims = jwsClaims.getBody();
    return claims.getSubject();
  }

  public Collection<? extends GrantedAuthority> getRolesFromJwtToken(String token) {
    Jws<Claims> jwsClaims = getClaims(token);
    if (jwsClaims == null) {
      return null;
    }

    Claims claims = jwsClaims.getBody();
    return AuthorityUtils
        .createAuthorityList(claims.get("roles", Collection.class));
  }

  public Long getOrganismFromJwtToken(String token) {
    Jws<Claims> jwsClaims = getClaims(token);
    if (jwsClaims == null) {
      return null;
    }

    Claims claims = jwsClaims.getBody();
    return claims.get("organism", Long.class);
  }



}
