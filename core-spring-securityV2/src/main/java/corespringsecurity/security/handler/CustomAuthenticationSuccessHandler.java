package corespringsecurity.security.handler;


import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    //이전에 사용자가 가려고했던 데이터
    private RequestCache requestCache = new HttpSessionRequestCache();

    //
    private RedirectStrategy redirectStrategy =new DefaultRedirectStrategy();


    //인증을 성공하면 사용전 클라가 요청했던 곳으로 보내준다
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(request, response, authentication);

        setDefaultTargetUrl("/");

        //인증전 사용자가 요청했던 정보들
        SavedRequest savedRequest = requestCache.getRequest(request,response);

        //정보 널체크
        if(savedRequest != null){
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request,response,targetUrl);

        }else{
            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
        }
    }
}