package com.mycompany.webapp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j2;

@Controller
@Log
public class HomeController {
	
	@RequestMapping("/")
	public String home() {
		log.info("실행");
		return "home";
	}
}
