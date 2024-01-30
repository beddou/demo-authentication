package com.testAuthentication.demo.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//for Angular Client (withCredentials)
//@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials="true")
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
  @GetMapping("/all")
  public String allAccess() {
    return "Public Content.";
  }

  @GetMapping("/user/{organism}")
  //@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN') or #organism == authentication.principal.organism")
  @PreAuthorize(" #organism == authentication.principal.organism")
  public String userAccess(@PathVariable int organism) {
    return "User Content.";
  }

  @GetMapping("/mod/{organism}")
 // @PreAuthorize("hasRole('MODERATOR')")
 @PreAuthorize(" hasRole('MODERATOR') and #organism == authentication.principal.organism")
  public String moderatorAccess(@PathVariable int organism) {
    return "Moderator Board.";
  }

  @GetMapping("/admin/{organism}")
  //@PreAuthorize("hasRole('ADMIN')")
  @PreAuthorize(" hasRole('ADMIN') and #organism == authentication.principal.organism")
  public String adminAccess(@PathVariable int organism) {
    return "Admin Board.";
  }
}
