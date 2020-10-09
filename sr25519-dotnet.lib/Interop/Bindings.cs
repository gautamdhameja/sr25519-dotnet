using System;
using System.Runtime.InteropServices;

namespace sr25519_dotnet.lib.Interop
{
    /// <summary>
    /// The P/Invoke bindings for the sr25519crust dll, generated from Rust code.
    /// </summary>
    internal sealed class Bindings
    {
        /// <summary>
        /// Perform a hard derivation on a secret.
        /// </summary>
        /// <param name="keypair_out">Output buffer for keypair.</param>
        /// <param name="pair_ptr">Input keypair.</param>
        /// <param name="cc_ptr">SR25519 chain code input.</param>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_derive_keypair_hard",
            SetLastError = true)]
        internal static extern void DeriveKeypairHard(
            [Out] byte[] keypair_out,
            byte[] pair_ptr, byte[] cc_ptr);

        /// <summary>
        /// Perform a soft derivation on a secret.
        /// </summary>
        /// <param name="keypair_out">Output buffer for keypair.</param>
        /// <param name="pair_ptr">Input keypair.</param>
        /// <param name="cc_ptr">SR25519 chain code input.</param>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_derive_keypair_soft",
            SetLastError = true)]
        internal static extern void DeriveKeypairSoft(
            [Out] byte[] keypair_out,
            byte[] pair_ptr, byte[] cc_ptr);

        /// <summary>
        /// Perform a derivation on a publicKey
        /// </summary>
        /// <param name="pubkey_out">Output buffer for public key.</param>
        /// <param name="public_ptr">Input public key.</param>
        /// <param name="cc_ptr">SR25519 chain code input.</param>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_derive_public_soft",
            SetLastError = true)]
        internal static extern void DerivePublicSoft(
            [Out] byte[] pubkey_out,
            byte[] public_ptr, byte[] cc_ptr);

        /// <summary>
        /// Generate keypair from seed.
        /// </summary>
        /// <param name="keypair_out">Output buffer for public key.</param>
        /// <param name="seed">Input seed.</param>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_keypair_from_seed",
            SetLastError = true)]
        internal static extern void KeypairFromSeed(
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
            EntryPoint = "sr25519_sign",
            SetLastError = true)]
        internal static extern void Sign(
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
            EntryPoint = "sr25519_verify",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        internal static extern bool Verify(
            byte[] signature_ptr, byte[] message_ptr,
            ulong message_length, byte[] public_ptr);

        /// <summary>
        /// Sign the provided message using a Verifiable Random Function and
        /// if the result is less than param limit provide the proof.
        /// </summary>
        /// <param name="out_and_proof_ptr"></param>
        /// <param name="keypair_ptr"></param>
        /// <param name="message_ptr"></param>
        /// <param name="message_length"></param>
        /// <param name="limit_ptr"></param>
        /// <returns></returns>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_vrf_sign_if_less",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Struct)]
        internal static extern VrfResult VrfSignIfLess(
            [Out] byte[] out_and_proof_ptr, byte[] keypair_ptr,
            byte[] message_ptr, ulong message_length, byte[] limit_ptr);

        /// <summary>
        /// Verify a signature produced by a VRF with its original input and the corresponding proof and
        /// check if the result of the function is less than the threshold.
        /// NOTE: If errors, is_less field of the returned structure is not meant to contain a valid value.
        /// </summary>
        /// <param name="out_and_proof_ptr"></param>
        /// <param name="keypair_ptr"></param>
        /// <param name="message_ptr"></param>
        /// <param name="message_length"></param>
        /// <param name="limit_ptr"></param>
        /// <returns></returns>
        [DllImport("sr25519crust",
            CallingConvention = CallingConvention.Cdecl,
            ExactSpelling = true,
            EntryPoint = "sr25519_vrf_verify",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Struct)]
        internal static extern VrfResult VrfVerify(
            byte[] public_ptr,
            byte[] message_ptr, ulong message_length,
            byte[] output_ptr, byte[] proof_ptr,
            byte[] threshold_ptr);
    }
}
