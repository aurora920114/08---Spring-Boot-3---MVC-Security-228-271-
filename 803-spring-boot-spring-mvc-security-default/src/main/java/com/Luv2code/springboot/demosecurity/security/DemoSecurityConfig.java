package com.Luv2code.springboot.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {
    @Bean
    public InMemoryUserDetailsManager userDetailsManager() { //InMemoryUserDetailsManage -> 用於管理內存中用戶資料的 class

        UserDetails john = User.builder()
                .username("john")
                .password("{noop}test123")  // "{noop}" 表示不對密碼進行加密
                .roles("EMPLOYEE")
                .build();

        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}test123")
                .roles("EMPLOYEE", "MANAGER")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}test123")
                .roles("EMPLOYEE", "MANAGER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(john, mary, susan);//用於在內存中管理用戶資料
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { //配置安全過濾鏈 (SecurityFilterChain

        //authorizeHttpRequests 用來配置授權規則
        //anyRequest().authenticated()表示所有請求都需要經過身份驗證(必須登錄才能訪問任何資源)
        http.authorizeHttpRequests(configurer ->
                        configurer
                                .anyRequest().authenticated()
                )
                .formLogin(form ->
                        form
                                .loginPage("/showMyLoginPage") //指定自定義的登錄頁面 URL()
                                .loginProcessingUrl("/authenticateTheUser")
                                //指定處理登錄請求的 URL，用戶提交表單時，表單指向URL，Spring Security 會自動處理身份驗證邏輯。
                                .permitAll() //允許所有用戶（含未經身份驗證）訪問登錄頁面和登錄處理 URL。確保用戶可以訪問登錄頁面以進行身份驗證。
                )
                .logout(logout ->
                                logout.permitAll()
                );
        return http.build();
    }
}
