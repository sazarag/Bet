using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Repository.Model
{
    public class DropDownModel
    {
        public string text { get; set; }
        public string id { get; set; }
    }

    public class LocalRecords
    {
        public int assignmentId { get; set; }
        public List<LocalRecord> localRecords { get; set; }
    }

    public class LocalRecord
    {
        public string key { get; set; }
        public string checkInDate { get; set; }
        public string checkOutDate { get; set; }
        //public string assignedments { get; set; }
        // public AssignedRoom[] assignedRooms { get; set; }

        public LocalRecord()
        {
        }
    }
    
}
