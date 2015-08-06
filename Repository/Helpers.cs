using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Repository
{
    public static class Helpers
    {
        public static string GetSplittedItem(string wholeText, string searchedText)
        {
            if (wholeText == null) { return ""; }
            string[] t = wholeText.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

            Dictionary<string, string> dictionary =
                                  t.ToDictionary(s => s.Split('=')[0], s => s.Split('=')[1]);
            if (!dictionary.ContainsKey(searchedText)) { 
                return ""; 
            }
            return dictionary[searchedText];
        }
        public static Dictionary<string, string> GetSplittedItem(string wholeText)
        {
            if (wholeText == null) { return null; }
            string[] t = wholeText.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

            Dictionary<string, string> dictionary =
                t.ToDictionary(s => s.Split('=')[0], s => s.Split('=').Length > 1 ? s.Split('=')[1] : "");

            return dictionary;
        }
    }
}
