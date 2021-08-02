using System.Runtime.InteropServices;
using sr25519_dotnet.lib.Models;

namespace sr25519_dotnet.lib.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    public struct VrfResult
    {
        private readonly Sr25519SignatureResult result;
        private readonly byte isLess;

        public Sr25519SignatureResult Result
        {
            get { return result; }
        }

        public bool IsLess
        {
            get { return isLess != 0; }
        }
    }
}