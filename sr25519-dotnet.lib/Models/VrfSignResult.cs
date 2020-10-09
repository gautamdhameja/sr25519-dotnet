using System;

namespace sr25519_dotnet.lib.Models
{
    public class VrfSignResult
    {
        public byte[] Output { get; private set; }
        public byte[] Proof { get; private set; }

        public VrfSignResult(byte[] vrfOutputAndProof)
        {
            // if (public_key.Length != Constants.SR25519_PUBLIC_SIZE &&
            //     secret_key.Length != Constants.SR25519_SECRET_SIZE)
            // {
            //     throw new SR25519KeypairException(StringConstants.BadKeySizeMessage);
            // }

            this.Output = new byte[Constants.SR25519_VRF_OUTPUT_SIZE];
            this.Proof = new byte[Constants.SR25519_VRF_PROOF_SIZE];
            Buffer.BlockCopy(vrfOutputAndProof, 0, this.Output, 0, Constants.SR25519_VRF_OUTPUT_SIZE);
            Buffer.BlockCopy(vrfOutputAndProof, Constants.SR25519_VRF_OUTPUT_SIZE, this.Proof, 0, Constants.SR25519_VRF_PROOF_SIZE);
        }
    }
}