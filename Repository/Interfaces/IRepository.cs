using Repository.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Repository.Interfaces
{
    public interface IRepository
    {
        #region General
        Task<List<HistoryLog>> GetHistoryLogs(string id);
        Task<bool> CreateHistoryLog(string uId, string entityKey);
        #endregion
        #region AspNetUsers
        Task<List<AspNetUser>> GetAspNetUsers();
        Task<AspNetUser> GetAspNetUser(string id);
        Task<object> GetPagedAspNetUserItems(jQueryDataTableParamModel param);
        Task<bool> CreateAspNetUser(AspNetUser aspNetUser);
        Task<bool> EditAspNetUser(AspNetUser aspNetUser, string newPassword);
        Task<bool> DeleteAspNetUser(string id);
        #endregion
        
        #region Entites
        Task<object> GetPagedTopEntitiesItems(jQueryDataTableParamModel param);
        Task<Entity> GetEntity(string key);
        Task<bool> EditEntity(Entity entity);
        Task<bool> CreateEntity(Entity entity, int? number);
        Task<bool> DeleteEntity(string key);
        #endregion
        #region Assignments
        Task<Assignment> GetAssignment(int assignmentId, string userId);
        Task<Assignment> GetAssignment(int id);
        Task<bool> EditAssignment(Assignment assignment);
        Task<bool> CreateAssignment(Assignment assignment);
        Task<bool> DeleteAssignment(int id);
        Task<List<Assignment>> GetAssignments(string userId);
        Task<object> GetPagedAssignmentItems(jQueryDataTableParamModel param);
        #endregion
    }
}
