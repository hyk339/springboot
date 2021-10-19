package com.mycompany.webapp.security;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

import lombok.extern.slf4j.Slf4j;

@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Resource
	private DataSource dataSource;
	
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
			.failureUrl("/security/loginError"); 		//default: /login?error
		
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
		auth.jdbcAuthentication()
			.dataSource(dataSource) //지금 우리는 dataSource 객체가 없다 그래서 주입해야한다.
			//DB에서 가져올 사용자 정보 조회 설정
			.usersByUsernameQuery("SELECT mid, mpassword, menabled FROM member WHERE mid=?")
			.authoritiesByUsernameQuery("SELECT mid, mrole FROM member WHERE mid=?")
			//패스워드 인코딩 방법 설정
			.passwordEncoder(passwordEncoder()); 		//default: DelegatingPasswordEncoder //password를 저장할 때 어떻게 password를 바꿀 것이냐
			
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		log.info("실행");
		//권한 계층 설정(default 웹 보안 표현식을 다루는자)
		DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
		handler.setRoleHierarchy(roleHierarchyImpl());
		web.expressionHandler(handler);
		web.ignoring()
			.antMatchers("/bootstrap-4.6.0-dist/**")
			.antMatchers("/css/**")
			.antMatchers("/images/**")
			.antMatchers("/jquery/**")
			.antMatchers("/favicon.ico");
	}
	
	//필요에 의해서 한것
	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		//PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		return passwordEncoder;
	}
	
	//권한 계층을 참조하기 위해 HttpSecurity에서 사용하기 때문에 관리빈으로 반드시 동록해야함
	@Bean
	public RoleHierarchyImpl roleHierarchyImpl() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
		return roleHierarchyImpl;
	}
	
}
