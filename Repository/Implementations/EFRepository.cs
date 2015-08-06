using Repository.Model;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.SqlServer;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using Repository.Interfaces;

namespace Repository.Implementations
{
    public class EFRepository : IRepository
    {
        private LockDBEntities db = new LockDBEntities(); 

        #region General
        public async Task<List<HistoryLog>> GetHistoryLogs(string id)
        {
            return await db.HistoryLogs.Where(h => h.UserId == id).ToListAsync();
        }
        public async Task<bool> CreateHistoryLog(string uId, string entityKey)
        {
            db.HistoryLogs.Add(new HistoryLog
            {
                UserId = uId,
                EntityKey = entityKey,
                LoginDate = DateTime.UtcNow
            } );
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        #endregion  
        #region AspNetUsers
        public async Task<List<AspNetUser>> GetAspNetUsers()
        {
            return await db.AspNetUsers.ToListAsync();
        }
        public async Task<AspNetUser> GetAspNetUser(string id)
        {
            return await db.AspNetUsers.FindAsync(id);
        }
        public async Task<bool> EditAspNetUser(AspNetUser aspNetUser, string newPassword)
        {
            db.Entry(aspNetUser).State = EntityState.Modified;
            db.Entry(aspNetUser).Property(prop => prop.CreateDate).IsModified = false;
            db.Entry(aspNetUser).Property(prop => prop.UpdateDate).IsModified = false;
            db.Entry(aspNetUser).Property(prop => prop.PasswordHash).IsModified = false;
            db.Entry(aspNetUser).Property(prop => prop.SecurityStamp).IsModified = false;
            aspNetUser.Id = aspNetUser.Id.Trim();
            aspNetUser.Email = aspNetUser.Email.Trim();
            aspNetUser.PhoneNumber = aspNetUser.PhoneNumber == null ? aspNetUser.PhoneNumber : aspNetUser.PhoneNumber.Trim();
            aspNetUser.UserName = aspNetUser.UserName.Trim();
            if (newPassword != null)
            {
                Microsoft.AspNet.Identity.PasswordHasher hash = new Microsoft.AspNet.Identity.PasswordHasher();
                aspNetUser.PasswordHash = hash.HashPassword(newPassword);
            }
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                string errorStr = ex.Message;
                return false;
            }
        }
        public async Task<bool> DeleteAspNetUser(string id)
        {
            AspNetUser aspNetUser = await GetAspNetUser(id);
            db.AspNetUsers.Remove(aspNetUser);
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        public async Task<object> GetPagedAspNetUserItems(jQueryDataTableParamModel param)
        {
            var usersCount = await db.AspNetUsers.CountAsync();

            var users = from r in db.AspNetUsers
                        select r;

            if (param.searchColumn != null)
            {
                if (param.searchColumn.Length > 0 && !String.IsNullOrWhiteSpace(param.searchColumn[0]))
                {
                    var temp = param.searchColumn[0].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        users = users.Where(r => SqlFunctions.PatIndex(temp, r.Id.ToLower()) > 0);
                    else if (temp.StartsWith("<"))
                        users = users.Where(r => String.Compare(r.Id.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        users = users.Where(r => String.Compare(r.Id.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        users = users.Where(r => r.Id.ToLower() != temp.Substring(1));
                    else
                        users = users.Where(r => r.Id.ToLower() == temp);

                }
                if (param.searchColumn.Length > 1 && !String.IsNullOrWhiteSpace(param.searchColumn[1]))
                {
                    var temp = param.searchColumn[1].ToLowerInvariant();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        users = users.Where(r => SqlFunctions.PatIndex(temp, r.UserName) > 0);
                    else if (temp.StartsWith("<"))
                        users = users.Where(r => String.Compare(r.UserName.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        users = users.Where(r => String.Compare(r.UserName.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        users = users.Where(r => r.UserName.ToLower() != temp.Substring(1));
                    else
                        users = users.Where(r => r.UserName.ToLower() == temp);

                }
                if (param.searchColumn.Length > 2 && !String.IsNullOrWhiteSpace(param.searchColumn[2]))
                {
                    var temp = param.searchColumn[2].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        users = users.Where(r => SqlFunctions.PatIndex(temp, r.Email) > 0);
                    else if (temp.StartsWith("<"))
                        users = users.Where(r => String.Compare(r.Email.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        users = users.Where(r => String.Compare(r.Email.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        users = users.Where(r => r.Email.ToLower() != temp.Substring(1));
                    else
                        users = users.Where(r => r.Email.ToLower() == temp);

                }
                if (param.searchColumn.Length > 3 && !String.IsNullOrWhiteSpace(param.searchColumn[3]))
                {
                    var temp = param.searchColumn[3].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        users = users.Where(r => SqlFunctions.PatIndex(temp, r.PhoneNumber) > 0);
                    else if (temp.StartsWith("<"))
                        users = users.Where(r => String.Compare(r.PhoneNumber.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        users = users.Where(r => String.Compare(r.PhoneNumber.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        users = users.Where(r => r.PhoneNumber.ToLower() != temp.Substring(1));
                    else
                        users = users.Where(r => r.PhoneNumber.ToLower() == temp);

                }
                if (param.searchColumn.Length > 4 && !String.IsNullOrWhiteSpace(param.searchColumn[4]))
                {
                    var temp = param.searchColumn[4].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        users = users.Where(r => SqlFunctions.PatIndex(temp, r.AccessFailedCount.ToString()) > 0);
                    else if (temp.StartsWith("<"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        users = users.Where(r => r.AccessFailedCount < tempToNumber);
                    }
                    else if (temp.StartsWith(">"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        users = users.Where(r => r.AccessFailedCount > tempToNumber);
                    }
                    else if (temp.StartsWith("~"))
                    {
                        users = users.Where(r => r.AccessFailedCount.ToString() != temp.Substring(1));
                    }
                    else
                        users = users.Where(r => r.AccessFailedCount.ToString().ToLower().Contains(temp));

                }
            }

            switch (param.orderByCol)
            {
                case 0:
                    users = param.orderDirection == "asc" ? users.OrderBy(r => r.Id) : users.OrderByDescending(r => r.Id);
                    break;
                case 1:
                    users = param.orderDirection == "asc" ? users.OrderBy(r => r.UserName) : users.OrderByDescending(r => r.UserName);
                    break;
                case 2:
                    users = param.orderDirection == "asc" ? users.OrderBy(r => r.Email) : users.OrderByDescending(r => r.Email);
                    break;
                case 3:
                    users = param.orderDirection == "asc" ? users.OrderBy(r => r.PhoneNumber) : users.OrderByDescending(r => r.PhoneNumber);
                    break;
                case 4:
                    users = param.orderDirection == "asc" ? users.OrderBy(r => r.AccessFailedCount) : users.OrderByDescending(r => r.AccessFailedCount);
                    break;

            }
            var filter = users;
            var filterCount = await filter.CountAsync();
            users = users.Skip(param.start).Take(param.length);
            var data = await users.ToListAsync();
            var dataFormatted = data.Select(x => new string[]  {
                x.Id,
                x.UserName,
                x.Email,
                x.PhoneNumber,
                x.AccessFailedCount.ToString(),
                ""
             });
            return new
            {
                recordsTotal = usersCount,
                recordsFiltered = filterCount,
                data = dataFormatted
            };
        }
        public async Task<bool> CreateAspNetUser(AspNetUser aspNetUser)
        {
            aspNetUser.CreateDate = DateTime.UtcNow;
            aspNetUser.UpdateDate = DateTime.UtcNow;
            aspNetUser.Id = Guid.NewGuid().ToString();
            Microsoft.AspNet.Identity.PasswordHasher hash = new Microsoft.AspNet.Identity.PasswordHasher();
            aspNetUser.PasswordHash = hash.HashPassword(aspNetUser.PasswordHash.Trim());
            aspNetUser.SecurityStamp = Guid.NewGuid().ToString();
            db.AspNetUsers.Add(aspNetUser);
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        #endregion
        
        #region Entities
        public async Task<object> GetPagedTopEntitiesItems(jQueryDataTableParamModel param)
        {
            var rAdminCount = await db.Entities.CountAsync();
            var rAdmin = from r in db.Entities
                         select r;

            if (param.searchColumn != null)
            {
                if (param.searchColumn.Length > 0 && !String.IsNullOrWhiteSpace(param.searchColumn[0]))
                {
                    var temp = param.searchColumn[0].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        rAdmin = rAdmin.Where(r => SqlFunctions.PatIndex(temp, r.Key.ToLower()) > 0);
                    else if (temp.StartsWith("<"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Key.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Key.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        rAdmin = rAdmin.Where(r => r.Key.ToLower() != temp.Substring(1));
                    else
                        rAdmin = rAdmin.Where(r => r.Key.ToLower() == temp);

                }
                if (param.searchColumn.Length > 1 && !String.IsNullOrWhiteSpace(param.searchColumn[1]))
                {
                    var temp = param.searchColumn[1].ToLowerInvariant();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        rAdmin = rAdmin.Where(r => SqlFunctions.PatIndex(temp, r.Attributes) > 0);
                    else if (temp.StartsWith("<"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Attributes.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Attributes.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        rAdmin = rAdmin.Where(r => r.Attributes.ToLower() != temp.Substring(1));
                    else
                        rAdmin = rAdmin.Where(r => r.Attributes.ToLower() == temp);

                }
                if (param.searchColumn.Length > 2 && !String.IsNullOrWhiteSpace(param.searchColumn[2]))
                {
                    var temp = param.searchColumn[2].ToLowerInvariant();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        rAdmin = rAdmin.Where(r => SqlFunctions.PatIndex(temp, r.Type) > 0);
                    else if (temp.StartsWith("<"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Type.ToLower(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        rAdmin = rAdmin.Where(r => String.Compare(r.Type.ToLower(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        rAdmin = rAdmin.Where(r => r.Type.ToLower() != temp.Substring(1));
                    else
                        rAdmin = rAdmin.Where(r => r.Type.ToLower() == temp);

                }

                if (param.searchColumn.Length > 3 && !String.IsNullOrWhiteSpace(param.searchColumn[3]))
                {
                    var temp = param.searchColumn[3].ToUpper();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        rAdmin = rAdmin.Where(r => SqlFunctions.PatIndex(temp, r.SortKey.ToString()) > 0);
                    else if (temp.StartsWith("<"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        rAdmin = rAdmin.Where(r => r.SortKey < tempToNumber);
                    }
                    else if (temp.StartsWith(">"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        rAdmin = rAdmin.Where(r => r.SortKey > tempToNumber);
                    }
                    else if (temp.StartsWith("~"))
                        rAdmin = rAdmin.Where(r => r.SortKey.ToString().ToLower() != temp.Substring(1));
                    else
                        rAdmin = rAdmin.Where(r => r.SortKey.ToString().ToUpper() == temp);

                }


            }

            switch (param.orderByCol)
            {
                case 0:
                    rAdmin = param.orderDirection == "asc" ? rAdmin.OrderBy(r => r.Key) : rAdmin.OrderByDescending(r => r.Key);
                    break;
                case 1:
                    rAdmin = param.orderDirection == "asc" ? rAdmin.OrderBy(r => r.Attributes) : rAdmin.OrderByDescending(r => r.Attributes);
                    break;
                case 2:
                    rAdmin = param.orderDirection == "asc" ? rAdmin.OrderBy(r => r.Type) : rAdmin.OrderByDescending(r => r.Type);
                    break;
                case 3:
                    rAdmin = param.orderDirection == "asc" ? rAdmin.OrderBy(x => x.SortKey) : rAdmin.OrderByDescending(x => x.SortKey);
                    break;
            }
            var filter = rAdmin;
            var filterCount = await filter.CountAsync();
            rAdmin = rAdmin.Skip(param.start).Take(param.length);
            var data = await rAdmin.ToListAsync();
            var dataFormatted = data.Select(x => new string[]  {
                x.Key,
                x.Attributes != null? ( x.Attributes.Length > 100 ? x.Attributes.Substring(0,100) + " ...": x.Attributes):"" ,
                x.Type,
                x.SortKey.ToString(),
                ""
             });
            return new
            {
                recordsTotal = rAdminCount,
                recordsFiltered = filterCount,
                data = dataFormatted
            };
        }

        public async Task<Entity> GetEntity(string key)
        {
            if (!String.IsNullOrEmpty(key))
            {
                return await db.Entities.Where(q => q.Key.Equals(key, StringComparison.CurrentCultureIgnoreCase)).FirstOrDefaultAsync();

                //object[] id = { key };
                //return await db.Entities.FindAsync(id);
            }
            return null;
        }
        public async Task<bool> EditEntity(Entity entity)
        {
            db.Entry(entity).State = EntityState.Modified;

            db.Entry(entity).Property(prop => prop.CreateDate).IsModified = false;
            entity.Attributes = entity.Attributes != null ? entity.Attributes.Trim() : "";
            entity.UpdateDate = DateTime.UtcNow;
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public async Task<bool> CreateEntity(Entity entity, int? number)
        {
            entity.CreateDate = DateTime.UtcNow;
            entity.UpdateDate = DateTime.UtcNow;
            entity.SortKey = entity.SortKey.HasValue ? entity.SortKey.Value : 0;
            entity.Key = entity.Key.Trim();
            entity.Attributes = entity.Attributes != null ? entity.Attributes.Trim() : "";
            bool hasParent = true;
            
            var checkEntity = await GetEntity(entity.Key);
            if (checkEntity == null)
            {
                db.Entry(entity).State = EntityState.Added;
                db.Entities.Add(entity);
            }
            if (number.HasValue && number.Value > 0)
            {
                int sortKeyBase = entity.SortKey.Value;
                for (int i = 0; i < number.Value; i++)
                {
                    db.Entities.Add(new Entity { Key = entity.Key + "/" + (i + 1), SortKey = sortKeyBase + (i + 1) });
                }
            }
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public async Task<bool> DeleteEntity(string key)
        {

            Entity e = await GetEntity(key);
            db.Entities.Remove(e);
            
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        #endregion
        #region Assignments
        public async Task<Assignment> GetAssignment(int assignmentId, string userId)
        {
            return await (from use in db.AspNetUsers
                          join assi in db.Assignments on use.Id equals assi.UserId
                          where (use.Id == userId && assi.AssignmentId == assignmentId)
                          select assi).FirstOrDefaultAsync();
        }

        public async Task<Assignment> GetAssignment(int id)
        {
            return await db.Assignments                
                .Include(e => e.AspNetUser)
                .Where(e => e.AssignmentId == id)
                .FirstOrDefaultAsync();
        }
        public async Task<bool> EditAssignment(Assignment assignment)
        {

            db.Entry(assignment).State = EntityState.Modified;
            db.Entry(assignment).Property(prop => prop.UpdateDate).IsModified = false;
            db.Entry(assignment).Property(prop => prop.CreateDate).IsModified = false;
            assignment.Key = assignment.Key != null ? assignment.Key.Trim() : null;
            
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        public async Task<bool> CreateAssignment(Assignment assignment)
        {
            assignment.CreateDate = DateTime.UtcNow;
            assignment.UpdateDate = DateTime.UtcNow;
            db.Entry(assignment).State = EntityState.Added;
            assignment.Key = assignment.Key != null ? assignment.Key.Trim() : null;

            db.Assignments.Add(assignment);
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        public async Task<bool> DeleteAssignment(int id)
        {
            Assignment assignment = await db.Assignments.FindAsync(id);
            db.Assignments.Remove(assignment);
            try
            {
                await db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        public async Task<List<Assignment>> GetAssignments(string userId)
        {
            return await (from use in db.AspNetUsers
                          join assi in db.Assignments on use.Id equals assi.UserId
                          where (use.Id == userId)
                          select assi).ToListAsync(); 
        }
        public async Task<object> GetPagedAssignmentItems(jQueryDataTableParamModel param)
        {
            var assignmentsCount = await db.Assignments.CountAsync();
            var assignments = from r in db.Assignments
                               select r;

            if (param.searchColumn != null)
            {
                if (param.searchColumn.Length > 0 && !String.IsNullOrWhiteSpace(param.searchColumn[0]))
                {
                    var temp = param.searchColumn[0].ToUpper();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        assignments = assignments.Where(r => SqlFunctions.PatIndex(temp, r.AssignmentId.ToString()) > 0);
                    else if (temp.StartsWith("<"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        assignments = assignments.Where(r => r.AssignmentId < tempToNumber);
                    }
                    else if (temp.StartsWith(">"))
                    {
                        int tempToNumber = 0;
                        Int32.TryParse(temp.Substring(1), out tempToNumber);
                        assignments = assignments.Where(r => r.AssignmentId > tempToNumber);
                    }
                    else if (temp.StartsWith("~"))
                        assignments = assignments.Where(r => r.AssignmentId.ToString().ToLower() != temp.Substring(1));
                    else
                        assignments = assignments.Where(r => r.AssignmentId.ToString().ToUpper() == temp);

                }
                if (param.searchColumn.Length > 1 && !String.IsNullOrWhiteSpace(param.searchColumn[1]))
                {
                    var temp = param.searchColumn[1].ToLower();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        assignments = assignments.Where(r => SqlFunctions.PatIndex(temp, r.UserId.ToString().ToLower()) > 0);
                    
                    else if (temp.StartsWith("~"))
                        assignments = assignments.Where(r => r.UserId.ToString().ToLower() != temp.Substring(1));
                    else
                        assignments = assignments.Where(r => r.UserId.ToString().ToLower() == temp);

                }

                if (param.searchColumn.Length > 2 && !String.IsNullOrWhiteSpace(param.searchColumn[2]))
                {
                    var temp = param.searchColumn[2].ToUpper();
                    if (temp.Contains('%') || temp.Contains('_') || temp.Contains('[') || temp.Contains(']') || temp.Contains('^') || temp.Contains('!'))
                        assignments = assignments.Where(r => SqlFunctions.PatIndex(temp, r.Key) > 0);
                    else if (temp.StartsWith("<"))
                        assignments = assignments.Where(r => String.Compare(r.Key.ToUpper(), temp.Substring(1)) < 0);
                    else if (temp.StartsWith(">"))
                        assignments = assignments.Where(r => String.Compare(r.Key.ToUpper(), temp.Substring(1)) > 0);
                    else if (temp.StartsWith("~"))
                        assignments = assignments.Where(r => r.Key.ToUpper() != temp.Substring(1));
                    else
                        assignments = assignments.Where(r => r.Key.ToUpper() == temp);
                }
            }

            switch (param.orderByCol)
            {
                case 0:
                    assignments = param.orderDirection == "asc" ? assignments.OrderBy(r => r.AssignmentId) : assignments.OrderByDescending(r => r.AssignmentId);
                    break;
                case 1:
                    assignments = param.orderDirection == "asc" ? assignments.OrderBy(r => r.UserId) : assignments.OrderByDescending(r => r.UserId);
                    break;
                case 2:
                    assignments = param.orderDirection == "asc" ? assignments.OrderBy(r => r.Key) : assignments.OrderByDescending(r => r.Key);
                    break;
                
            }
            var filter = assignments;
            var filterCount = await filter.CountAsync();
            assignments = assignments.Skip(param.start).Take(param.length);
            var data = await assignments.ToListAsync();
            var dataFormatted = data.Select(x => new string[]  {
                x.AssignmentId.ToString(),
                x.UserId.ToString(),
                x.Key,                
                ""
             });
            return new
            {
                recordsTotal = assignmentsCount,
                recordsFiltered = filterCount,
                data = dataFormatted
            };
        }

        public async Task<object> GetUsersCurrentAssignments(string userId)
        {
            return await db.Assignments
                .Where(x => x.UserId == userId)
                .Select(x => new
                {
                    EntityKey = x.Key,
                    EntityAttributes = x.Entity.Attributes
                })
                .ToListAsync();
        }
        #endregion
    }    
}
