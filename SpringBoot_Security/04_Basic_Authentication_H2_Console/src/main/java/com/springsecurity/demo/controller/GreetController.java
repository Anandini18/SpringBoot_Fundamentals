package com.springsecurity.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetController {

    /*
      - Hitting url for h2-console : http://localhost:8080/h2-console/
      - Enter user & password -> H2 console is enabled.
      - Url & username will be given in the console.
     */

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello!";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String sayUserHello(){
        return "Hello, User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String sayAdminHello(){
        return "Hello, Admin!";
    }


}
