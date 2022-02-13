package corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username or password";


        //아이디나 패스워드가 불일치 할경우
        if(exception instanceof BadCredentialsException){

            errorMessage = "Invalid Username or Password";


            //DetailsSource = 추가정보 가 불일치 할경우
        }else if(exception instanceof InsufficientAuthenticationException){

            errorMessage = "Invalid Secret key";

        }

        //에러메세지
        //이 url로 가기위한 처리해줘야함 -> /login*
        setDefaultFailureUrl("/login?error=true&exception= " + exception.getMessage());

        super.onAuthenticationFailure(request,response,exception);
    }
}
