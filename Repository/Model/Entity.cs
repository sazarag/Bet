//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Repository.Model
{
    using System;
    using System.Collections.Generic;
    
    public partial class Entity
    {
        public Entity()
        {
            this.Assignments = new HashSet<Assignment>();
            this.HistoryLogs = new HashSet<HistoryLog>();
        }
    
        public string Key { get; set; }
        public string Attributes { get; set; }
        public Nullable<int> SortKey { get; set; }
        public Nullable<System.DateTime> CreateDate { get; set; }
        public Nullable<System.DateTime> UpdateDate { get; set; }
        public string Type { get; set; }
    
        public virtual ICollection<Assignment> Assignments { get; set; }
        public virtual ICollection<HistoryLog> HistoryLogs { get; set; }
    }
}
