package org.bookbajaar.config.security;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Repository;


/**
 * @author Mreetunjay 
 * This CustomAuthenticationSuccessHandler is used to define the redirect strategy after successful authentication
 */
@Repository("customAuthenticationSuccessHandler")
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	
    protected Log logger = LogFactory.getLog(this.getClass());
    
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
    	handle(request, response, authentication);
        clearAuthenticationAttributes(request);
    }

    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(authentication,request);
        System.out.println("REDIRECT : == "+targetUrl);
        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    
    protected String determineTargetUrl(Authentication authentication,HttpServletRequest request) {
    	String redirectUrl= (String) request.getSession().getAttribute("targetUrl");
    	if (redirectUrl != null) {
            // we do not forget to clean this attribute from session
    		request.getSession().removeAttribute("targetUrl");
    	}
        boolean isSuperAdmin = false;
        boolean isSalesAdmin = false;
        boolean isPublisher = false;
        boolean isCustomer = false;

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (GrantedAuthority grantedAuthority : authorities) {
            if (grantedAuthority.getAuthority().equals("ROLE_SUPER_ADMIN")) {
            	isSuperAdmin = true;
                break;
            } else if (grantedAuthority.getAuthority().equals("ROLE_SALES_ADMIN")) {
            	isSalesAdmin = true;
                break;
            } else if (grantedAuthority.getAuthority().equals("ROLE_PUBLISHER")) {
            	isPublisher = true;
                break;
            } else if (grantedAuthority.getAuthority().equals("ROLE_CUSTOMER")) {
            	isCustomer = true;
                break;
            }
        }

        if (isSuperAdmin) {
            return "/sales/dashboard";
        } else if (isSalesAdmin) {
        	return "/sales/dashboard";
        }else if (isPublisher) {
        	return "/publisher/dashboard";
        }else if (isCustomer) {
        	System.out.println(redirectUrl+" ------------------------------------------------USRL");
        	if(redirectUrl!=null && (redirectUrl.contains("checkout") || redirectUrl.contains("shipping-address"))){
        		return "/secure/shipping-address";
        	}else if(redirectUrl!=null && redirectUrl.contains("track")){
        		return "/track/order-list";
        	}else{
        		System.out.println("EEEEEELLLLLSSSSSEEEEE");
        		return "/";
        	}
        }else {
            throw new IllegalStateException();
        }
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }
   
}