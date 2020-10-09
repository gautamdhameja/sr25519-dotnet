using System;
using sr25519_dotnet.lib.Exceptions;
using sr25519_dotnet.lib.Interop;

namespace sr25519_dotnet.lib.Models
{
    public class VrfSignResult : VrfVerifyResult
    {
        public byte[] Output { get; private set; }
        public byte[] Proof { get; private set; }

        public VrfSignResult(VrfResult result, byte[] vrfOutputAndProof) : base(result)
        {
            if (vrfOutputAndProof.Length != (
                Constants.SR25519_VRF_OUTPUT_SIZE + Constants.SR25519_VRF_PROOF_SIZE))
            {
                throw new SR25519VrfException(StringConstants.BadVrfResultSizeMessage);
            }

            Output = new byte[Constants.SR25519_VRF_OUTPUT_SIZE];
            Proof = new byte[Constants.SR25519_VRF_PROOF_SIZE];
            Buffer.BlockCopy(vrfOutputAndProof, 0, this.Output, 0, Constants.SR25519_VRF_OUTPUT_SIZE);
            Buffer.BlockCopy(vrfOutputAndProof, Constants.SR25519_VRF_OUTPUT_SIZE, this.Proof, 0, Constants.SR25519_VRF_PROOF_SIZE);
        }
    }
}