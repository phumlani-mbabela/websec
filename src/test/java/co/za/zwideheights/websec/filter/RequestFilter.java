package co.za.zwideheights.websec.filter;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import co.za.zwideheights.websec.validate.PreventAttack;

public class RequestFilter implements Filter {

	FilterConfig filterConfig = null;

	public void init(FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		Enumeration<String> parameterNames = servletRequest.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			String name = parameterNames.nextElement();
			String value = servletRequest.getParameter(name);
			servletRequest.setAttribute(name, PreventAttack.PreventCrossSiteScripting(PreventAttack.PreventSQLInjection(value)));
		}
		filterChain.doFilter(servletRequest, servletResponse);
	}

}
