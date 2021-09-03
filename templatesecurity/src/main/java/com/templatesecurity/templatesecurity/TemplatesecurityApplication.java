package com.templatesecurity.templatesecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
//@EntityScan("${entity.package}") uncomment this line for select entity scan dir
public class TemplatesecurityApplication {


    public static void main(String[] args) {
        SpringApplication.run(TemplatesecurityApplication.class, args);
    }

}
