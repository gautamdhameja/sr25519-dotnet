namespace sr25519_dotnet.lib.Models
{
    /// <summary>
    /// The SR25519 Keypair
    /// </summary>
    public class SR25519Keypair
    {
        public byte[] Public { get; set; }

        public byte[] Secret { get; set; }
    }
}
