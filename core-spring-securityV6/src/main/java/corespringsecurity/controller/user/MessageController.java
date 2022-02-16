package corespringsecurity.controller.user;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/message")
    public String mypage()throws Exception{

        return "user/message";
    }

    @GetMapping("/api/messages")
    //ajax 방식이라 json형식으로 바디에 리턴해야함
    @ResponseBody
    public String apiMessage(){

        return "messageOk";
    }
}
