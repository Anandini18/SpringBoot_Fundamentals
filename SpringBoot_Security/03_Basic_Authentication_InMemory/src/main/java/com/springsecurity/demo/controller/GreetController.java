package com.springsecurity.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetController {

    /*
    - In application.properties :
      - spring.security.user.name=admin
      - spring.security.user.password=1234
     */

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello!";
    }

    // PreAuthorize is used to authorize the end point before executing the method
    // Using PreAuthorize, we are telling spring security that only candidates with "user" role can access this particular endpoint
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
