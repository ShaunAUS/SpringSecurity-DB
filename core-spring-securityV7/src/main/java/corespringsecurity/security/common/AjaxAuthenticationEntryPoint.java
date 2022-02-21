package corespringsecurity.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//인증 처리가 안된(익명사용자) 가  자원에 접근했을경우

public class AjaxAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {


        //인증 처리 안되고 자원 접근시 클라에게 에러 보낸다
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UnAuthorized");

    }
}
