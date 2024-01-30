package com.testAuthentication.demo.security.jwt;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.testAuthentication.demo.security.services.UserDetailsImpl;

//import com.testAuthentication.demo.security.services.UserDetailsServiceImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      String jwt = parseJwt(request);
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

        this.createAuthentication(jwt).ifPresent(authentication -> {
          SecurityContextHolder.getContext().setAuthentication(authentication);
        });
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e);
    }

    filterChain.doFilter(request, response);
  }

  private String parseJwt(HttpServletRequest request) {
    String jwt = jwtUtils.getJwtFromCookies(request);
    return jwt;
  }

  //// **************************************************/
  public Optional<Authentication> createAuthentication(String token) {

    Jws<Claims> jwsClaims = jwtUtils.getClaims(token);
    if (jwsClaims == null) {
      return Optional.empty();
    }

    Collection<? extends GrantedAuthority> authorities = jwtUtils.getRolesFromJwtToken(token);

    String subject = jwtUtils.getUserNameFromJwtToken(token);
    Long organism = jwtUtils.getOrganismFromJwtToken(token);

    UserDetailsImpl principal = new UserDetailsImpl(null, subject, "email", organism, "", authorities);

    return Optional.of(new UsernamePasswordAuthenticationToken(principal, token, authorities));
  }

}
