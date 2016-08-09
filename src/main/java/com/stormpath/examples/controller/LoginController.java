package com.stormpath.examples.controller;

import com.stormpath.sdk.application.Application;
import com.stormpath.sdk.client.Client;
import com.stormpath.sdk.oauth.Authenticators;
import com.stormpath.sdk.oauth.IdSiteAuthenticationRequest;
import com.stormpath.sdk.oauth.OAuthBearerRequestAuthentication;
import com.stormpath.sdk.oauth.OAuthBearerRequestAuthenticationResult;
import com.stormpath.sdk.oauth.OAuthGrantRequestAuthenticationResult;
import com.stormpath.sdk.oauth.OAuthRequests;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class LoginController {

    @Autowired
    Application application;

    @Autowired
    Client client;

    @RequestMapping("/login")
    public String login() {

        String idSiteUrl = application.newIdSiteUrlBuilder()
            .setCallbackUri("http://localhost:8080/idSiteCallback")
            .build();

        return "redirect:" + idSiteUrl;
    }

    @RequestMapping(path = "/logout", method = POST)
    public String logout(HttpServletResponse res) {

        Cookie accessTokenCookie = new Cookie("access_token", "");
        accessTokenCookie.setMaxAge(0);

        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setMaxAge(0);

        res.addCookie(accessTokenCookie);
        res.addCookie(refreshTokenCookie);

        String idSiteUrl = application.newIdSiteUrlBuilder()
            .setCallbackUri("http://localhost:8080/")
            .forLogout()
            .build();

        return "redirect:" + idSiteUrl;
    }

    @RequestMapping("/idSiteCallback")
    public String idSiteCallback(HttpServletRequest req, HttpServletResponse res) {

        String jwtResponse = req.getParameter("jwtResponse");

        IdSiteAuthenticationRequest idSiteAuthenticationRequest = OAuthRequests.IDSITE_AUTHENTICATION_REQUEST
            .builder()
            .setToken(jwtResponse)
            .build();

        OAuthGrantRequestAuthenticationResult result = Authenticators.ID_SITE_AUTHENTICATOR
            .forApplication(application)
            .authenticate(idSiteAuthenticationRequest);

        Cookie accessTokenCookie = new Cookie("access_token", result.getAccessTokenString());
        accessTokenCookie.setHttpOnly(true);

        Cookie refreshTokenCookie = new Cookie("refresh_token", result.getRefreshTokenString());
        refreshTokenCookie.setHttpOnly(true);

        res.addCookie(accessTokenCookie);
        res.addCookie(refreshTokenCookie);

        return "redirect:/";
    }

    @RequestMapping("/")
    public String home(HttpServletRequest req, Model model) {
        String accessTokenString = getAccessTokenString(req);

        if (accessTokenString != null) {
            OAuthBearerRequestAuthentication oAuthBearerRequestAuthentication = OAuthRequests.OAUTH_BEARER_REQUEST
                .builder()
                .setJwt(accessTokenString)
                .build();

            OAuthBearerRequestAuthenticationResult result = Authenticators.OAUTH_BEARER_REQUEST_AUTHENTICATOR
                .forApplication(application)
                .authenticate(oAuthBearerRequestAuthentication);

            model.addAttribute("account", result.getAccount());
        }

        return "home";
    }

    private String getAccessTokenString(HttpServletRequest req) {
        for (Cookie cookie : req.getCookies()) {
            if ("access_token".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
