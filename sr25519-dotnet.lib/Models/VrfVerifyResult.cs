using sr25519_dotnet.lib.Interop;

namespace sr25519_dotnet.lib.Models
{
    public class VrfVerifyResult
    {
        public Sr25519SignatureResult Result { get; protected set; }
        public bool IsLess { get; protected set; }

        public VrfVerifyResult(VrfResult result)
        {
            Result = result.Result;
            IsLess = result.IsLess;
        }
    }
}