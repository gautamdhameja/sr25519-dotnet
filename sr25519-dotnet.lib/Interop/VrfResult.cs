using System;
using System.Runtime.InteropServices;

namespace sr25519_dotnet.lib.Interop
{
    public enum Sr25519SignatureResult : uint
    {
        Ok,
        EquationFalse,
        PointDecompressionError,
        ScalarFormatError,
        BytesLengthError,
        NotMarkedSchnorrkel,
        MuSigAbsent,
        MuSigInconsistent,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct VrfResult
    {
        private readonly Sr25519SignatureResult result;
        private readonly bool isLess;

        public Sr25519SignatureResult Result
        {
            get { return result; }
        }

        public bool IsLess
        {
            get { return isLess; }
        }
    }
}