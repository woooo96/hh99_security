package com.sparta.springsecurity.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class CustomSecurityFilter extends OncePerRequestFilter {
//OncePerRequestFilter라는 기본적으로 제공되는 추상 클래스를 상속받아 재정의
    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;


    //http 요청이 들어오면 filter를 통해 contorller로 들어오게 되는데 해당 작업을 하기 위해서 사용됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //httpservlet을 통해 들어완 데이터에서 getParameter를 통해 key 값이 username/password인 value값을 받아온다
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        System.out.println("username = " + username);
        System.out.println("password = " + password);
        System.out.println("request.getRequestURI() = " + request.getRequestURI());


        if(username != null && password  != null && (request.getRequestURI().equals("/api/user/login") || request.getRequestURI().equals("/api/test-secured"))){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 비밀번호 확인
            if(!passwordEncoder.matches(password, userDetails.getPassword())) {
                throw new IllegalAccessError("비밀번호가 일치하지 않습니다.");
            }

            // 인증 객체 생성 및 등록
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            //authenticatino 객체를 만드는데 UsernamePasswordAuthenticationToken 내부에 userDetailsService를 통해 검증된 UserDetials 객체, credentaals, Authorities 값을 넣어 저장한다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            //SecurityContext타입의 context에 해당 내용을 저장한다
            context.setAuthentication(authentication);

            //저장된 SecurityContext를 SecurityContextHolder에 저장한다.
            SecurityContextHolder.setContext(context);
        }

        //filter를 통과하게 되면 다음 필터로 넘어가게 되고, 에러가 발생하면 exception이 발생됨
        filterChain.doFilter(request,response);
    }
}