package com.yaoba.app.web.m.weixin.mp;

import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import me.chanjar.weixin.mp.api.WxMpService;
import me.chanjar.weixin.mp.bean.result.WxMpOAuth2AccessToken;
import me.chanjar.weixin.mp.bean.result.WxMpUser;

import org.apache.commons.lang3.StringUtils;
import org.apache.struts2.convention.annotation.Result;
import org.apache.struts2.convention.annotation.Results;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springside.modules.utils.web.struts2.Struts2Utils;

import com.google.common.collect.Maps;
import com.opensymphony.xwork2.ActionSupport;
import com.yaoba.app.entity.account.User;
import com.yaoba.app.entity.weixin.WeixinUser;
import com.yaoba.app.service.account.UserManager;
import com.yaoba.app.service.system.ParameterManager;
import com.yaoba.app.service.weixin.WeixinUserManager;
import com.yaoba.app.service.weixin.WxMpManager;

/**
 * 
 * @author yaoba
 * @version 创建时间：2016-2-28 下午03:14:05
 */

@Results({ @Result(name = "reload", location = "bind-user.action", type = "redirect") })
public class BindUserAction extends ActionSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1412880463907879750L;
	private WeixinUserManager weixinUserManager;
	private UserManager userManager;
	private ParameterManager parameterManager;

	private List<User> userList;

	private String loginName;
	private String password;
	private String userId;

	/**
	 * OAuth2.0验证
	 * 
	 * @throws Exception
	 */
	public void oauth2() throws Exception {
		System.out.println("oauth2");
		WxMpService wxMpService = WxMpManager.getWxMpService();

		HttpServletRequest request = Struts2Utils.getRequest();
		HttpServletResponse response = Struts2Utils.getResponse();

		String code = request.getParameter("code");
		WxMpOAuth2AccessToken token = wxMpService.oauth2getAccessToken(code);
		String userId = token.getOpenId();

		Struts2Utils.getSession().setAttribute(WeixinUserManager.WEIXIN_USER_ID, userId);
		System.out.println(userId);

		String redirectUrl = request.getParameter("redirectUrl");
		System.out.println("oauth2:redirectUrl=" + redirectUrl);
		response.sendRedirect(redirectUrl);
	}

	@Override
	public String execute() throws Exception {

		String weixinUserId = (String) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_USER_ID);
		if (weixinUserId == null) {
			// 取微信的用户ID，如果ID为空去OAuth2验证取用户的ID

			WxMpService wxMpService = WxMpManager.getWxMpService();

			String systemUrl = parameterManager.getParameterValue(ParameterManager.SYSTEM_URL);
			String successUrl = "./bind-user.action";
			String redirectUrl = systemUrl + "m/weixin/mp/bind-user!oauth2.action?redirectUrl=" + URLEncoder.encode(successUrl, "utf-8");
			System.out.println("execute1");
			System.out.println(redirectUrl);
			String url = wxMpService.oauth2buildAuthorizationUrl(redirectUrl, "snsapi_base", "state");
			System.out.println("execute2");
			System.out.println(url);

			HttpServletResponse response = Struts2Utils.getResponse();
			response.sendRedirect(url);
			return null;
		}

		WeixinUser weixinUser = weixinUserManager.findUnique(Restrictions.eq("id", weixinUserId));
		if (weixinUser == null) {
			// 系统里也要创建一微信用户
			WxMpService wxMpService = WxMpManager.getWxMpService();
			WxMpUser wxMpUser = wxMpService.userInfo(weixinUserId, "zh_CN");
			weixinUser = new WeixinUser();
			weixinUser.setId(wxMpUser.getOpenId());
			weixinUser.setName(wxMpUser.getNickname());

			weixinUser.setSex(wxMpUser.getSex());
			weixinUser.setCountry(wxMpUser.getCountry());
			weixinUser.setProvince(wxMpUser.getProvince());
			weixinUser.setCity(wxMpUser.getCity());
			weixinUserManager.insert(weixinUser);
		}

		userList = weixinUser.getUserList();

		return SUCCESS;

	}

	/**
	 * 绑定保存
	 * 
	 * @throws Exception
	 */
	public void save() throws Exception {

		Map<String, Object> json = Maps.newHashMap();
		json.put("success", true);

		String weixinUserId = (String) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_USER_ID);

		if (weixinUserId == null) {
			json.put("success", false);
			json.put("message", "请重新登录。");
			Struts2Utils.renderJson(json);
			return;
		}

		User user = userManager.findByLoginName(StringUtils.upperCase(loginName));
		if (user == null || !StringUtils.equals(user.getPassword(), password)) {
			json.put("success", false);
			json.put("message", "登录名或密码错误。");
			Struts2Utils.renderJson(json);
			return;
		}

		WeixinUser weixinUser = weixinUserManager.findUnique(Restrictions.eq("id", weixinUserId));

		if (!user.getWeixinUserList().contains(weixinUser)) {
			user.getWeixinUserList().add(weixinUser);
			weixinUser.getUserList().add(user);
			userManager.save(user);
		}
		System.out.println(user.getWeixinUserNames());

		json.put("message", "绑定成功");
		Struts2Utils.renderJson(json);

	}

	/**
	 * 解绑
	 * 
	 * @throws Exception
	 */
	public String unbundling() throws Exception {
		String weixinUserId = (String) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_USER_ID);
		if (weixinUserId == null) {
			return execute();
		}

		User user = userManager.get(userId);
		WeixinUser weixinUser = weixinUserManager.get(weixinUserId);
		if (user.getWeixinUserList().contains(weixinUser)) {
			user.getWeixinUserList().remove(weixinUser);
			weixinUser.getUserList().remove(user);
			userManager.save(user);
		}
		return "reload";
	}

	@Autowired
	public void setWeixinUserManager(WeixinUserManager weixinUserManager) {
		this.weixinUserManager = weixinUserManager;
	}

	@Autowired
	public void setUserManager(UserManager userManager) {
		this.userManager = userManager;
	}

	@Autowired
	public void setParameterManager(ParameterManager parameterManager) {
		this.parameterManager = parameterManager;
	}

	public void setLoginName(String loginName) {
		this.loginName = loginName;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public List<User> getUserList() {
		return userList;
	}

}
