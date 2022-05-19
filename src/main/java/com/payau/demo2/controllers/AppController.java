package com.payau.demo2.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AppController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/authenticated")
    public String authenticated() {
        return "authenticated";
    }

    @GetMapping("/client")
    public String client() {
        return "client";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

}
