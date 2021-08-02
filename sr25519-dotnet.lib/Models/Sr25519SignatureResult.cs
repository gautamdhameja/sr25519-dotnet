namespace sr25519_dotnet.lib.Models
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
}