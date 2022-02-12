package corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private ObjectMapper objectMappe = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {


        String errorMessage = "Invalid Username or Password";

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE );


        //다양한 경우에 대한 메세지
        //아이디나 패스워드가 불일치 할경우
        if(exception instanceof BadCredentialsException){

            errorMessage = "Invalid Username or Password";


            //DetailsSource = 추가정보 가 불일치 할경우
        }else if(exception instanceof InsufficientAuthenticationException){

            errorMessage = "Invalid Secret key";

        }


        //클라에게 json방식으로 오류메세지 보내기
        objectMappe.writeValue(response.getWriter(),errorMessage);


    }
}
