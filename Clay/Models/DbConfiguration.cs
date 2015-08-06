using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.SqlServer;
using System.Linq;
using System.Web;

namespace Clay.Models
{
    public class MyConfiguration : DbConfiguration
    {
        public MyConfiguration()
        {
            SetExecutionStrategy("System.Data.SqlClient", () => new SqlAzureExecutionStrategy());
            SetDefaultConnectionFactory(new MyConnectionFactory());
            SetProviderServices(SqlProviderServices.ProviderInvariantName, SqlProviderServices.Instance);
        }
    }

    public class MyConnectionFactory : IDbConnectionFactory
    {
        private SqlConnectionFactory scf = null;
        private string constr = null;
        public MyConnectionFactory()
        {
            // Get the connection string within the connection string
            constr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["LockDBEntities"].ConnectionString;
            constr = constr.Substring(constr.IndexOf("\"") + 1);
            constr = constr.Substring(0, constr.IndexOf("\"")) + ';';
            scf = new SqlConnectionFactory(constr);
        }

        System.Data.Common.DbConnection IDbConnectionFactory.CreateConnection(string nameOrConnectionString)
        {
            return scf.CreateConnection(constr);
        }
    } 
}