package com.mycompany.webapp.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import lombok.extern.slf4j.Slf4j;

@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.info("configure(HttpSecurity http) 실행");
		//로그인 방식 설정
		http.formLogin() 								//FormLoginConfiguer configuer = ~~ 이렇게 받아서 잘 쓰지는 않고 바로쓴다.
			.loginPage("/security/loginForm")			 //요청 경로이므로 @requestmapping 메서드를 만들어야한다. //default: /login(GET)
			.usernameParameter("mid")					//default: username //설정안하면
			.passwordParameter("mpassword")				//default: password //설정안하면
			.loginProcessingUrl("/login")   			//default: /login(POST) post방식으로 로그인을 요청해야한다.
			.defaultSuccessUrl("/security/content")
			.failureUrl("security/loginError"); 		//default: /login?error
		
		//로그아웃 설정
		http.logout()
			.logoutUrl("/logout") 						//default: /logout
			.logoutSuccessUrl("/security/content");
		
		//URL 권한 설정
		http.authorizeRequests()
			.antMatchers("/security/admin/**").hasAuthority("ROLE_ADMIN")
			.antMatchers("/security/manager/**").hasAuthority("ROLE_MANAGER")
			.antMatchers("/security/user/**").authenticated()
			.antMatchers("/**").permitAll();
		
		//권한 없음(403)일 경우 이동할 경로 설정
		http.exceptionHandling().accessDeniedPage("/security/accessDenied");
		
		//CSRF 비활성화
		http.csrf().disable();
		
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.info("configure(AuthenticationManagerBuilder auth) 실행");
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		log.info("실행");
	}
}
