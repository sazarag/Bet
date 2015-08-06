using Repository.Implementations;
using Repository.Interfaces;
using Repository.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Clay.Controllers
{
    [Authorize(Roles = "Admin")]
    public class EntityController : Controller
    {
        // GET: Entity
        private IRepository repo;

        public EntityController()
        {
            repo = new EFRepository();
        }
        public ActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<JsonResult> DriveDataTable(jQueryDataTableParamModel param)
        {
            return Json(await repo.GetPagedTopEntitiesItems(param));
        }

        public async Task<ActionResult> Form(string key)
        {
            Entity e = null;
            if (!String.IsNullOrEmpty(key))
            {
                e = await repo.GetEntity(key);
            }
            return View(e);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<bool> Create([Bind(Include = "Key,Attributes,Type,SortKey,CreateDate,UpdateDate")] Entity entity, int? number)
        {
            if (!ModelState.IsValid)
            {
                return false;
            }
            if (!await repo.CreateEntity(entity, number))
            {
                return false;
            }
            return true;

        }


        // POST: Reservations/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<bool> Edit([Bind(Include = "Key,Attributes,Type,SortKey,CreateDate,UpdateDate")] Entity entity)
        {
            if (!ModelState.IsValid)
            {
                return false;
            }
            if (!await repo.EditEntity(entity))
            {
                return false;
            }
            return true;
        }

        // GET: Reservations/Delete/5
        public async Task<bool> Delete(string key)
        {
            if (!await repo.DeleteEntity(key))
            {
                return false;
            }
            return true;
        }


    }
}