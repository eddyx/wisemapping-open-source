/*
 *    Copyright [2022] [wisemapping]
 *
 *   Licensed under WiseMapping Public License, Version 1.0 (the "License").
 *   It is basically the Apache License, Version 2.0 (the "License") plus the
 *   "powered by wisemapping" text requirement on every single page;
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the license at
 *
 *       http://www.wisemapping.org/license
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.wisemapping.rest;

import com.wisemapping.exceptions.WiseMappingException;
import com.wisemapping.rest.model.RestJwtUser;
import com.wisemapping.security.JwtTokenUtil;
import com.wisemapping.service.RecaptchaService;
import com.wisemapping.service.RegistrationException;
import com.wisemapping.validator.Messages;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/restful")
public class JwtAuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private RecaptchaService captchaService;

    @Value("${app.registration.captcha.enabled:true}")
    private Boolean registrationCaptchaEnabled;

    private static final String REAL_IP_ADDRESS_HEADER = "X-Real-IP";
    private static final Logger logger = LogManager.getLogger();

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<String> createAuthenticationToken(@RequestBody RestJwtUser user, @NotNull HttpServletRequest request, @NotNull HttpServletResponse response) throws WiseMappingException, BindException {
        final BindException errors = new RegistrationException(user, "authenticate");

        if (registrationCaptchaEnabled) {
            String remoteIp = request.getHeader(REAL_IP_ADDRESS_HEADER);
            if (remoteIp == null || remoteIp.isEmpty()) {
                remoteIp = request.getRemoteAddr();
            }

            final String recaptcha = user.getRecaptcha();
            if (recaptcha != null) {
                final String reCaptchaResponse = captchaService.verifyRecaptcha(remoteIp, recaptcha);
                if (reCaptchaResponse != null && !reCaptchaResponse.isEmpty()) {
                    errors.rejectValue("recaptcha", reCaptchaResponse);
                }
            } else {
                errors.rejectValue("recaptcha", Messages.CAPTCHA_LOADING_ERROR);
            }
        } else {
            logger.warn("captchaEnabled is enabled.Recommend to enable it for production environments.");
        }

        if (errors.hasErrors()) {
            throw errors;
        }

        // Is a valid user ?
        authenticate(user.getEmail(), user.getPassword());
        final String result = jwtTokenUtil.doLogin(response, user.getEmail());

        return ResponseEntity.ok(result);
    }

    private void authenticate(@NotNull String username, @NotNull String password) throws WiseMappingException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException | BadCredentialsException e) {
            throw new WiseMappingException(e.getMessage(), e);
        }
    }
}