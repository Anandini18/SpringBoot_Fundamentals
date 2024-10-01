package com.springsecurity.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetController {

    // Without security, we are able to access the "/hello" endpoint
    // After adding spring-security starter dependency in the pom.xml file, we can't able to access "/hello"
    // Now, appearing is the default Login-SignUp Page
    // By default, Username -> "user" & Password will be given in the log as, Using generated security password: 70d794b3-7ea9-4488-8445-5858c91b400d
    // After sign in , we are able to access "/hello" endpoint
    // This is default security provided by spring boot, using DefaultSecurityChain
    // For logout, hit http://localhost:8080/logout, then we can simply logout.

    /*
    Important Points :
    - After adding spring-security dependency in the pom file, all the endpoints of entire file are being authenticated.
    - The default authentication is form (in-built) based authentication.
    - We can also add our desired manual username and password, instead of using default user, password.
    - In application.properties :
      - spring.security.user.name=admin
      - spring.security.user.password=1234
     */

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello!";
    }
}
