package com.ibm.examples.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.ibm.examples.exception.CustomException;

/**
 * This is the main filter class for our security purpose. The filter is applied
 * to each API (/**).
 * 
 * @author ClaudiuIova
 */
public class JWTTokenFilter extends GenericFilterBean {

	private JWTTokenProvider provider;

	public JWTTokenFilter(JWTTokenProvider provider) {
		this.provider = provider;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String token = provider.resolveToken((HttpServletRequest) request);
		try {
			if (token != null && provider.validateToken(token)) {
				Authentication auth = token != null ? provider.getAuthentication(token) : null;
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
			chain.doFilter(request, response);
		} catch (CustomException ex) {
			HttpServletResponse res = (HttpServletResponse) response;
			res.sendError(ex.getHttpStatus().value(), ex.getMessage());
			return;
		}
	}
}
