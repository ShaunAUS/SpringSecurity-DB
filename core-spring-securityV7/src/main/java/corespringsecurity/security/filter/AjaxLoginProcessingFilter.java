package corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import corespringsecurity.domain.dto.AccountDTo;
import corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {


    //Json 방식으로 온 데이터를 객체로 만든다
    private ObjectMapper objectMapper = new ObjectMapper();


    //조건 1
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }


    //조건 2
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {


        //Ajax인지 아닌지 확인
        if(!isAjax(request)){

            throw new IllegalStateException("Authenticatin is not supported");
        }

        //아이디와 비밀번호  AccountDTO 타입으로 받기
        AccountDTo accountDTo = objectMapper.readValue(request.getReader(), AccountDTo.class);

        //아아디나 비밀번호가 null이면 인증처리 x
        if(StringUtils.isEmpty(accountDTo.getUserName()) || StringUtils.isEmpty(accountDTo.getPassWord())){
            throw new IllegalStateException("username or password is empty");

        }

        //클라가 보낸 아이디와 패스워드 토큰에 넣기
        AjaxAuthenticationToken ajaxAuthenticationToken =new AjaxAuthenticationToken(accountDTo.getUserName(),accountDTo.getPassWord());


        //AuthenticationManager에게 사용자 정보가 들어있는 토큰을 준다 (인증하라고)
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }


    //Ajax인지 아닌지 헤더값과 비교하여 판단한다
    // 사용자가 요청할떄 헤더에 요청정보 담아서 보내는데 그정보값과 같은지 같지않은지 -> 미리 클라와 약속
    private boolean isAjax(HttpServletRequest request) {

        //요청 헤더 값이 이 값과 일치하면 Ajax
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))){

            return true;
        }

        return false;
    }














}
