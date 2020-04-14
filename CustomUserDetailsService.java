package org.bookbajaar.config.security;

import java.util.ArrayList;
import java.util.List;

import org.bookbajaar.model.User;
import org.bookbajaar.model.UserInfo;
import org.bookbajaar.model.UserRole;
import org.bookbajaar.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService{

	static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
	
	@Autowired
	private UserService userService;
	
	/*@Autowired
    private AuthenticationManager authenticationManager;*/
	
	@Transactional(readOnly=true)
	public UserDetails loadUserByUsername(String username)throws UsernameNotFoundException {
		
		User user = userService.loadUserByUsername(username);
		logger.info("User : {}", user);
		
		if(user==null){
			logger.info("User not found");
			throw new UsernameNotFoundException("Username not found");
		}else{
			return new UserInfo(username, user.getPassword(), true, true, true, true, getGrantedAuthorities(user), user.getUserPkId(), user.getName());
			
		}
			/*return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), 
				 true, true, true, true, getGrantedAuthorities(user));*/
	}

	
	private List<GrantedAuthority> getGrantedAuthorities(User user){
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		
		for(UserRole userRole : user.getUserRole()){
			logger.info("UserProfile : {}", userRole);
			authorities.add(new SimpleGrantedAuthority("ROLE_"+userRole.getRole().getRoleName()));
		}
		logger.info("authorities : {}", authorities);
		return authorities;
	}
	
	/*public void autologin(String username, String password) {
        UserDetails userDetails = loadUserByUsername(username);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            System.out.println("Login Successfully");
        }
    }*/
}
