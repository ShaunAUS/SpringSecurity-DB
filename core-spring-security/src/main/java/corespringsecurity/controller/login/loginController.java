package corespringsecurity.controller.login;


import corespringsecurity.domain.dto.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class loginController {



 //인증 실패시 로그인 페이지로 리다이렉트 이후 처리
 @GetMapping({"/login","api/login"})
 public String login(@RequestParam(value= "erroe", required = false)String error,
                     @RequestParam(value= "erroe", required = false)String exception, Model model){

  model.addAttribute("error", error);
  model.addAttribute("exception", exception);

  return"/login";
 }





 @GetMapping("/logout")
 public String logout(HttpServletRequest request, HttpServletResponse response){

  //로그인 했으면 securityContext 안에 인증에 성공한 authentication 객체가있다
  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

  if(authentication != null){
   //logout filter 에서사용
    new SecurityContextLogoutHandler().logout(request,response,authentication);
  }

  return"redirect:/login";
 }

 @GetMapping({"/denied","api/denied"})
 public String accessDenied(@RequestParam(value ="exception",required = false)String exception,Model model){

  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
  Account account = (Account) authentication.getPrincipal();

  model.addAttribute("username",account.getUserName());
  model.addAttribute("exception",exception);


  return "user/login/denied";
 }


}
