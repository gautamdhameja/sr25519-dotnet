using System.Runtime.InteropServices;

namespace sr25519_dotnet.lib.Interop
{
    /// <summary>
    /// The P/Invoke bindings for the sr25519crust dll generated from Rust code.
    /// </summary>
    internal class Bindings
    {
        /// <summary>
        /// Generate keypair from seed.
        /// </summary>
        /// <param name="keypair_out"></param>
        /// <param name="seed"></param>
        [DllImport("sr25519crust",
        CallingConvention = CallingConvention.Cdecl,
        ExactSpelling = true,
        SetLastError = true)]
        internal static extern void sr25519_keypair_from_seed(
        [Out] byte[] keypair_out, byte[] seed);

        /// <summary>
        /// Sign a message.
        /// </summary>
        /// <param name="signature_out"></param>
        /// <param name="public_ptr"></param>
        /// <param name="secret_ptr"></param>
        /// <param name="message_ptr"></param>
        /// <param name="message_length"></param>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            SetLastError = true)]
        internal static extern void sr25519_sign(
            [Out] byte[] signature_out, byte[] public_ptr, byte[] secret_ptr,
            byte[] message_ptr, ulong message_length);

        /// <summary>
        /// Verify a signature.
        /// </summary>
        /// <param name="signature_ptr"></param>
        /// <param name="message_ptr"></param>
        /// <param name="message_length"></param>
        /// <param name="public_ptr"></param>
        /// <returns></returns>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            SetLastError = true)]
        internal static extern bool sr25519_verify(
            byte[] signature_ptr, byte[] message_ptr,
            ulong message_length, byte[] public_ptr);
    }
}
