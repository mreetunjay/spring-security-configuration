package org.bookbajaar.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	@Qualifier("customUserDetailsService")
	UserDetailsService userDetailsService;
	
	@Autowired
	CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
/*
	@Autowired
	PersistentTokenRepository tokenRepository;*/

	@Autowired
	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
		auth.authenticationProvider(authenticationProvider());
	}

	/*@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/", "/list").access("hasRole('USER') or hasRole('ADMIN') or hasRole('DBA')")
				.antMatchers("/newuser/**", "/delete-user-*").access("hasRole('ADMIN')")
				.antMatchers("/edit-user-*").access("hasRole('ADMIN') or hasRole('DBA')")
				.and().formLogin().loginPage("/login").loginProcessingUrl("/login")
				.usernameParameter("ssoId").passwordParameter("password")
				.and().exceptionHandling().accessDeniedPage("/Access_Denied");
	}*/
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/","/books/**").permitAll()
				.antMatchers("/admin/**").access("hasRole('SUPER_ADMIN')")
				.antMatchers("/sales/**").access("hasRole('SUPER_ADMIN') or hasRole('SALES_ADMIN')")
				.antMatchers("/publisher/**").access("hasRole('PUBLISHER') or hasRole('SUPER_ADMIN') or hasRole('SALES_ADMIN')")
				.antMatchers("/secure/**","/track/**").access("hasRole('CUSTOMER')")
				.and().formLogin().loginPage("/login").loginProcessingUrl("/login")
				.successHandler(customAuthenticationSuccessHandler)
				.usernameParameter("username").passwordParameter("password")
				.and().exceptionHandling().accessDeniedPage("/Access_Denied");
	}

	/*@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }*/
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}

	/*@Bean
	public PersistentTokenBasedRememberMeServices getPersistentTokenBasedRememberMeServices() {
		PersistentTokenBasedRememberMeServices tokenBasedservice = new PersistentTokenBasedRememberMeServices(
				"remember-me", userDetailsService, tokenRepository);
		return tokenBasedservice;
	}*/

	@Bean
	public AuthenticationTrustResolver getAuthenticationTrustResolver() {
		return new AuthenticationTrustResolverImpl();
	}
	
	//added by mreetunjay to inject authenticationmanager
	@Bean(name="authenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
