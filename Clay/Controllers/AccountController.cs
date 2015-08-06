using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Clay.Models;
using Clay.Providers;
using Clay.Results;
using System.Net;
using System.Text;
using System.Configuration;
using System.Linq;

namespace Clay.Controllers
{
    public class AccountController : Controller
    {

        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        private ApplicationSignInManager _signInManager;

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set { _signInManager = value; }
        }

        //
        // POST: /Account/Login
        [System.Web.Mvc.HttpPost]
        //[RequireHttps]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode
        [System.Web.Mvc.AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            var user = await UserManager.FindByIdAsync(await SignInManager.GetVerifiedUserIdAsync());
            if (user != null)
            {
                var code = await UserManager.GenerateTwoFactorTokenAsync(user.Id, provider);
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [System.Web.Mvc.HttpPost]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }
        private bool GetCaptchaResponse()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://www.google.com/recaptcha/api/verify");
            request.Timeout = 30 * 1000;
            request.Method = "POST";
            request.UserAgent = "reCAPTCHA/ASP.NET";
            request.ContentType = "application/x-www-form-urlencoded";
            string ip = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            if (string.IsNullOrEmpty(ip))
                ip = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
            if (string.IsNullOrEmpty(ip))
                ip = "127.0.0.1";
            string formData = "privatekey=" + HttpUtility.UrlEncode(System.Configuration.ConfigurationManager.AppSettings["RecaptchaPrivateKey"]) +
                              "&remoteip=" + HttpUtility.UrlEncode(ip) +
                              "&challenge=" + HttpUtility.UrlEncode(Request.Form["recaptcha_challenge_field"]) +
                              "&response=" + HttpUtility.UrlEncode(Request.Form["recaptcha_response_field"]);
            byte[] formbytes = Encoding.UTF8.GetBytes(formData);
            request.ContentLength = formData.Length;
            using (System.IO.Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(formbytes, 0, formbytes.Length);
                requestStream.Close();
            }

            try
            {
                using (WebResponse httpResponse = request.GetResponse())
                {
                    using (System.IO.TextReader readStream = new System.IO.StreamReader(httpResponse.GetResponseStream(), Encoding.UTF8))
                    {
                        string[] result = readStream.ReadToEnd().Split(new string[] { "\n", @"\n" }, StringSplitOptions.RemoveEmptyEntries);
                        if ((result != null) && (result.Length == 2))
                        {
                            bool captchaOK = Convert.ToBoolean(result[0]);
                            if (!captchaOK)
                                ModelState.AddModelError("", result[1]);
                            return captchaOK;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                return false;
            }
            return false;
        }
        ////
        // GET: /Account/Register
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [System.Web.Mvc.HttpPost]
       // [RequireHttps]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model, string returnUrl)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    //if (GetCaptchaResponse())
                    //{

                        var user = new ApplicationUser { UserName = model.UserName, Email = model.Email };
                        user.Email = model.Email;
                        user.EmailConfirmed = false;
                        user.PhoneNumber = model.PhoneNumber;
                        var result = await UserManager.CreateAsync(user, model.Password);
                        //if (result.Succeeded)
                        //{
                        //    var code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                        //    var callbackUrl = Url.Action("ConfirmEmail", "Account",
                        //                                 new { userId = user.Id, code = code }, this.Request.Url.Scheme);

                        //    await UserManager.SendEmailAsync(user.Id,
                        //       "Confirm your account",
                        //       "Please confirm your account by clicking this link: <a href=\""
                        //                                       + callbackUrl + "\">link</a>");
                        //    return View("DisplayEmail");

                        //}
                        AddErrors(result);
                    //}
                }
                return RedirectToLocal(returnUrl);
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return View(model);
        }
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult Confirm(string Email)
        {
            ViewBag.Email = Email;
            return View();
        }

        //
        // GET: /Account/ForgotPassword
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [System.Web.Mvc.HttpPost]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                //|| !(await UserManager.IsEmailConfirmedAsync(user.Id))
                if (user == null)
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                var code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { UserId = user.Id, code = code }, this.Request.Url.Scheme);
                await UserManager.SendEmailAsync(user.Id, "Reset Password",
                "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");
                return View("ForgotPasswordConfirmation");
            }
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [System.Web.Mvc.HttpPost]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/SendCode
        [System.Web.Mvc.AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [System.Web.Mvc.HttpPost]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [System.Web.Mvc.AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            //ExternalLoginUserProfile profile; 
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }
            //else
            //{
            //    //save to db at this point 
            //    if(loginInfo.Login.LoginProvider.ToLower() == "twitter")
            //    {
            //        profile = new ExternalLoginUserProfile(loginInfo.DefaultUserName,                         
            //            loginInfo.ExternalIdentity.Claims.First(d => d.Type == "urn:twitter:screenname").Value,
            //            loginInfo.Email, 
            //            loginInfo.ExternalIdentity.Claims.First(d => d.Type == "urn:twitter:userid") != null ?
            //            Convert.ToInt64(loginInfo.ExternalIdentity.Claims.First(d => d.Type == "urn:twitter:userid").Value) : (long?)null,
            //            loginInfo.ExternalIdentity.Claims.First(d => d.Type == "urn:twitter:accesstoken").Value, loginInfo.ExternalIdentity.Claims.First(d => d.Type == "urn:twitter:accesstokensecret").Value, String.Empty, String.Empty);
            //    }

            //    else if(loginInfo.Login.LoginProvider.ToLower() == "google")
            //    {
            //        //finds URL 
            //        Regex regx = new Regex("https://([\\w+?\\.\\w+])+([a-zA-Z0-9\\~\\!\\@\\#\\$\\%\\^\\&amp;\\*\\(\\)_\\-\\=\\+\\\\\\/\\?\\.\\:\\;\\'\\,]*)?", RegexOptions.IgnoreCase);

            //        profile = new ExternalLoginUserProfile(loginInfo.DefaultUserName, loginInfo.DefaultUserName, loginInfo.Email, null, String.Empty, String.Empty,  
            //            loginInfo.ExternalIdentity.Claims.First(x => x.Type == "image") != null ?
            //            regx.Matches(loginInfo.ExternalIdentity.Claims.First(x => x.Type == "image").Value)[0].Value : String.Empty, 
            //            loginInfo.ExternalIdentity.Claims.First(x => x.Type == "gender") != null ?
            //            loginInfo.ExternalIdentity.Claims.First(x => x.Type == "gender").Value : String.Empty);
            //    }

            //    else if(loginInfo.Login.LoginProvider.ToLower() == "facebook")
            //    {                                        
            //        profile = new ExternalLoginUserProfile(loginInfo.DefaultUserName, loginInfo.DefaultUserName, loginInfo.Email,  Convert.ToInt64(loginInfo.ExternalIdentity.Claims.First(d => d.Type == "FacebookUserId").Value ), loginInfo.ExternalIdentity.Claims.First(d => d.Type == "FacebookAccessToken").Value, String.Empty, String.Empty, String.Empty); 

            //    }
            //    else //windows
            //    {
            //        profile = new ExternalLoginUserProfile(loginInfo.DefaultUserName, loginInfo.DefaultUserName, loginInfo.Email, null, String.Empty, String.Empty, String.Empty, String.Empty); 
            //    }

            //}

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [System.Web.Mvc.HttpPost]
        [System.Web.Mvc.AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);

                    //------Facebook external login db record
                    //if (info.ExternalIdentity.AuthenticationType.ToLowerInvariant() == "facebook") {  
                    //    var userObj = (from us in db.AspNetUserLogins where us.UserId.ToString() == user.Id.ToString() select us).First();
                    //    userObj.SocialId = Convert.ToInt64( info.ExternalIdentity.Claims.First(d => d.Type == "FacebookUserId").Value );
                    //    userObj.AccessToken = info.ExternalIdentity.Claims.First(d => d.Type == "FacebookAccessToken").Value;
                    //    db.SaveChanges();
                    //}

                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [System.Web.Mvc.HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [System.Web.Mvc.AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }


        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";
        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (String.IsNullOrEmpty(returnUrl))
                returnUrl = "~/";
            string url = "http://" + HttpContext.Request.Url.Authority + Url.Content(returnUrl);
            return Redirect(url);
            //if (Url.IsLocalUrl(returnUrl))
            //{
            //    return Redirect(returnUrl);
            //}
            //return RedirectToAction("Index", "Pick");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
                var loginInfo = context.HttpContext.GetOwinContext().Authentication.GetExternalLoginInfo();

            }
        }

        
    }
}
