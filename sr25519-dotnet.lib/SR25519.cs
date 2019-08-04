using sr25519_dotnet.lib.Models;
using System;
using sr25519_dotnet.lib.Interop;
using System.Text;

namespace sr25519_dotnet.lib
{
    /// <summary>
    /// SR25519 Operations.
    /// </summary>
    public class SR25519
    {
        /// <summary>
        /// Generates a SR25519 keypair from a hex seed string.
        /// </summary>
        /// <param name="seedHex">Seed string as hex.</param>
        /// <returns>SR25519Keypair</returns>
        public static SR25519Keypair GenerateKeypairFromSeed(string seedHex)
        {
            byte[] seedBytes = Utils.HexStringToByteArray(seedHex);

            var keys = new byte[Constants.SR25519_KEYPAIR_SIZE];
            Bindings.sr25519_keypair_from_seed(keys, seedBytes);

            var keypair = new SR25519Keypair();
            keypair.Secret = new byte[Constants.SR25519_SECRET_SIZE];
            keypair.Public = new byte[Constants.SR25519_PUBLIC_SIZE];
            Buffer.BlockCopy(keys, 0, keypair.Secret, 0, 64);
            Buffer.BlockCopy(keys, 64, keypair.Public, 0, 32);

            return keypair;
        }

        /// <summary>
        /// Signs a message and returns the signature.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="keypair">The keypair for signing.</param>
        /// <returns>Signature as byte[]</returns>
        public static byte[] Sign(string message, SR25519Keypair keypair)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            var signature = new byte[Constants.SR25519_SIGNATURE_SIZE];

            Bindings.sr25519_sign(
                signature, keypair.Public, 
                keypair.Secret, bytes, Convert.ToUInt64(bytes.Length));

            return signature;
        }

        /// <summary>
        /// Verify the signature of a signed message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The message signature.</param>
        /// <param name="publicKey">The public (verification) key.</param>
        /// <returns>True/False if the verification passed or failed.</returns>
        public static bool Verify(string message, byte[] signature, 
            byte[] publicKey)
        {
            bool result;
            try
            {
                var bytes = Encoding.UTF8.GetBytes(message);
                result = Bindings.sr25519_verify(
                    signature, bytes, Convert.ToUInt64(bytes.Length), 
                    publicKey);
            }
            catch (Exception)
            {
                return false;
            }

            return result;
        }
    }
}
