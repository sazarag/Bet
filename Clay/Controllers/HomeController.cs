using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Repository.Implementations;
using Repository.Interfaces;
using Repository.Model;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;
using System.Net;
using System.Text;
using System.Data.Entity.SqlServer;


namespace Clay.Controllers
{
    public class JsonResultObj
    {
        public bool updateResult { get; set; }
    }

    [Authorize]
    public class HomeController : Controller
    {
        private Repository.Implementations.EFRepository repo;

        public HomeController()
        {
            repo = new Repository.Implementations.EFRepository();
        }

        public async Task<ActionResult> Index()
        {
            var uid = User.Identity.GetUserId();
            List<Assignment> newAssignments = (await repo.GetAssignments(uid)).ToList<Assignment>();
            return View(newAssignments);
        }
    }
}
