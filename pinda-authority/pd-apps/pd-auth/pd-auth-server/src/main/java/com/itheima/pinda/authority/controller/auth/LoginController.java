package com.itheima.pinda.authority.controller.auth;

import com.itheima.pinda.authority.biz.service.auth.ValidateCodeService;
import com.itheima.pinda.authority.biz.service.auth.impl.AuthManager;
import com.itheima.pinda.authority.dto.auth.LoginDTO;
import com.itheima.pinda.authority.dto.auth.LoginParamDTO;
import com.itheima.pinda.base.BaseController;
import com.itheima.pinda.base.R;
import com.itheima.pinda.exception.BizException;
import com.itheima.pinda.log.annotation.SysLog;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 安逸i
 * @version 1.0
 */

@RestController
@RequestMapping("/anno")
@Api(value = "UserAuthController", tags = "登录")
@Slf4j
public class LoginController extends BaseController {

    // 注入验证码验证
    @Autowired
    private ValidateCodeService validateCodeService;

    @Autowired
    private AuthManager authManager;
    /**
     * 获取验证码
     * @param key
     * @param response
     * @throws IOException
     */
    @SysLog("获取验证码")
    @ApiOperation(value = "验证码", notes = "验证码")
    @GetMapping(value = "/captcha", produces = "image/png")
    public void captcha(@RequestParam(value = "key") String key,
                        HttpServletResponse response) throws IOException {
        this.validateCodeService.create(key, response);
    }

    /**
     *  登录验证
     * @param login
     * @return
     * @throws BizException
     */
    @SysLog("登录操作")
    @ApiOperation(value = "登录", notes = "登录")
    @PostMapping(value = "/login")
    public R<LoginDTO> login(@Validated @RequestBody LoginParamDTO login)
            throws BizException {
        log.info("account={}", login.getAccount());
        /// 比对验证码
        if (this.validateCodeService.check(login.getKey(), login.getCode())) {
            return this.authManager.login(login.getAccount(), login.getPassword());
        }
        return this.success(null);
    }

}
