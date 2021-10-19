package com.mycompany.webapp.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class CustomUserDetails extends User {
	
	private String useremail;
	
	public CustomUserDetails(
			String username, 
			String password,
			boolean enabled,
			Collection<? extends GrantedAuthority> authorities,
			String useremail) {
		super(username, password, enabled, true, true, true, authorities);
		//위 부분 코드는 그대로 두어야한다.
		//바꾸면 동작 안한다. spring이 기본적으로 필요한것이 username, password, authorities다.
		this.useremail = useremail;
	}

	public String getUseremail() {
		return useremail;
	}
	
}
