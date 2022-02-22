package corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import corespringsecurity.domain.entity.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {


        // AuthenticationProvider에서 보낸 토큰(인증성공 객체) 꺼내기
        Account account =(Account)authentication.getPrincipal();

        //클라에게 응답
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        //objectMapper가 인증성공한 account를 Json형식으로 클라에게 전달 해준다
        objectMapper.writeValue(response.getWriter(),account);
    }
}
