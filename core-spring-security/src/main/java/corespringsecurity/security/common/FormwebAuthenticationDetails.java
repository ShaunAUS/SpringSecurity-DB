package corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;


//사용자가 보내는 정보(username, password) 외에 추가적인 데이터 저장 클래스
//Requests 라는 객체를 통해 아이디/패스워드를 제외한 추가정보를 저장한다
public class FormwebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public String getSecretKey() {
        return secretKey;
    }



    public FormwebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        //클라로부터 전달돼는 추가 데이터 이름
        String secret_key = request.getParameter("secret_key");

    }
}
