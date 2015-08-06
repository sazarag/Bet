using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Repository.Model
{
    public class jQueryDataTableParamModel
    {
        //Paging first record indicator. This is the start point in the current data set (0 index based - i.e. 0 is the first record).
        public int start { get; set; }
        // global search keyword
        public string search { get; set; }
        // Number of records that should be shown in table
        public int length { get; set; }
        //represent the index of column which is to ordered 
        public int orderByCol { get; set; }
        //order direction (asc or desc)
        public string orderDirection { get; set; }

        public string[] searchColumn { get; set; }
    }
}
