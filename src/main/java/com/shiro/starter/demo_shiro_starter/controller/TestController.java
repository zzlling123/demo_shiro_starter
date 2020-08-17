package com.shiro.starter.demo_shiro_starter.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @RequestMapping("/login")
    public String login(String username,String password) {
        //添加用户认证信息
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(
                username,
                password
        );
        try {
            //进行验证，这里可以捕获异常，然后返回对应信息
            subject.login(usernamePasswordToken);
            //subject.checkRole("admin");
            //subject.checkPermissions("query", "add");
        } catch (AuthenticationException e) {
            //e.printStackTrace();
            return "账号或密码错误！";
        } catch (AuthorizationException e) {
            //e.printStackTrace();
            return "没有权限";
        }
        return "login success";
    }


    //注解验角色和权限
    @RequiresRoles("admin")
    @RequiresPermissions("user:insert")
    @RequestMapping("/index")
    public String index() {
        return "index!";
    }

    @ExceptionHandler(AuthorizationException.class)
    @RequestMapping("/403")
    public String noAuth(){
        return "403";
    }

    @RequestMapping("/success")
    public String success(){
        return "success";
    }

}
