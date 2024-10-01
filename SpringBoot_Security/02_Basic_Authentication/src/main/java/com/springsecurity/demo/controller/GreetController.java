package com.springsecurity.demo.controller;

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
}
