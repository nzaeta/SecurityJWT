package com.nzaeta.SecurityJWT.Controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
public class TestController {
    
    @GetMapping()
    public String probando() {
        return "Hola Mundo";
    }
    
    @Secured("COMPRADOR")
    @GetMapping("endpointComprador")
    public String endpointComprador() {
        return "Hola, soy un comprador";
    }
    
    @Secured("VENDEDOR")
    @GetMapping("endpointVendedor")
    public String endpointVendedor() {
        return "Hola, soy un vendedor";
    }
    
}