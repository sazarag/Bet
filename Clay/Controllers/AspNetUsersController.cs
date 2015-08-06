using Clay.Models;
using Repository.Interfaces;
using Repository.Implementations;
using Repository.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity;

namespace Clay.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AspNetUsersController : Controller
    {
        private IRepository repo;
        private ApplicationUserManager _userManager;

        public AspNetUsersController()
        {
            repo = new EFRepository();
        }

        // GET: AspNetUsers
        public ActionResult Index()
        {
            return View();
        }


        public async Task<ActionResult> Form(string id)
        {
            AspNetUser user = null;
            if (id != null)
            {
                user = await repo.GetAspNetUser(id);
            }
            return View(user);
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

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<JsonResult> DriveDataTable(jQueryDataTableParamModel param)
        {
            return Json(await repo.GetPagedAspNetUserItems(param));
        }

        // POST: AspNetUsers/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<bool> Create([Bind(Include = "UserName,Email,EmailConfirmed,PasswordHash,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled")] AspNetUser aspNetUser)
        {

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser();
                user.AccessFailedCount = 0;
                user.Email = aspNetUser.Email.Trim();
                user.EmailConfirmed = aspNetUser.EmailConfirmed;
                user.LockoutEnabled = aspNetUser.LockoutEnabled;
                user.LockoutEndDateUtc = aspNetUser.LockoutEndDateUtc;
                user.PhoneNumber = aspNetUser.PhoneNumber == null ? aspNetUser.PhoneNumber : aspNetUser.PhoneNumber.Trim();
                user.PhoneNumberConfirmed = aspNetUser.PhoneNumberConfirmed;
                user.TwoFactorEnabled = aspNetUser.TwoFactorEnabled;
                user.UserName = aspNetUser.UserName.Trim();

                try
                {
                    // Use the password hash as actual password
                    var res = await UserManager.CreateAsync(user, aspNetUser.PasswordHash);
                    if (!res.Succeeded)
                    {
                        return false;
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    return false;
                }
            }
            return true;

        }


        // POST: AspNetUsers/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<bool> Edit([Bind(Include = "Id,UserName,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,CreateDate,UpdateDate")] AspNetUser aspNetUser, string NewPassword)
        {
            if (ModelState.IsValid)
            {
                if (await repo.EditAspNetUser(aspNetUser, NewPassword))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            return false;
        }

        // GET: AspNetUsers/Delete/5
        public async Task<bool> Delete(string Id)
        {
            return await repo.DeleteAspNetUser(Id);
        }
    }
}