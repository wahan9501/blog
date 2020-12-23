using System;
using System.Numerics;
using System.Globalization;

namespace https_handshake
{
    class Program
    {
        static void Main(string[] args)
        {
            // RSAExample();

            var signature = "096fd858c07a340af492e44938202794cf8aca6485c640cc5870cf10346bfb01f0a9500d7e3f728afb2ff2e462917b41281a496a7f8f06815ce8dcbad6298adc3dee6abcb952d6283e37d20e1abd95f4ccf429cf138c7e43cece0f5062707231dcc857fb27bea88efb04a7e83405d4a1441e1fe272104c32a968c53f84a74a506a2b35714ff789055b08417b0786b3b0a00b46a2210a628de6b2f0e848872e21437bc92143bb4a694617b4897f2df26ad33e10ecff398fd147b5c01b731545a281c20fd6035e5250c9ed73ed3af7ee7b27dc16e8854614702efbc210adf5f4af3c860051acd3344db79831d19216e7a90a6c3bb417330b07b27e5b557a4219c2a8907f8f274a4ffc391fb0e0ef5a7182e5afe0f5f2ba61f8cc69f009e3db187b92d4bf0f60207065bd83b84c104b4e8b99475f4c2d161f738cb013b2386aad1d9da7021c6ede94fbac1634cbb70725ad203614ec8e1ed0fcc7c6e68e5e6b4573c9e8c231e2e39bb3e8a64756364d982290ed255142a4a597705ed10962da559c190942f5c79d42aab1d193dbccd21fcfd2f739064459becc02437c4397256b04c7f68f73679b1d77e60821f6f1a9fafa47f666090853c7157caa5851b81f350e63122ad2dbbdeee1a61dae4593b1023484b81b584e2a731ee62ac6595483486aad9d9c589494b7dfbb05ae7b66e3688b0a1d094ef1d8afe605e0f538029f32ee1";
            var public_N = "0f4c01959aa2a247c062131d1ee12f5816a94e3f6d14a2fe35db12e291438bccc955d2907d1f85d37f420d7b43f583a7a92ee8f3cfa2b0a72039e40d4eb8b8ef698f9e7f0ddef3c25f46c3384564fa7919348040df3029bc61a0ff8d1386fefc90097189b322a6c29a85d6eea07072381e19958a2d70185ffce6d47fae640917d731142a38a5a464b92294f3e7df3918339187c5e23830d6754a82811281dad84fee0f005057169d63849165617131dec04722380b3d6293837667a00b0f731f8c0804103c28927cb0f531afaf83ee6c065da94e75d7334b0686af6abd8e0154e5d1375d8fe44085b9d7d7fcf2a6a93e89fbfe7770a08836bc31bbe8d6ed90f27b9406b29552647a123915fdd0eb22c51a53ae37bff5a9fee13bc4b0dd842e6ba652bdb2236562884c4cc28b0248f155e58159b423ed1122724212a5cfb2a308b7c94acee650a03402ab08d630fb001f02f84590e7aa3e6ea43f8d481d55d5b46342fd4a2071d88a52247f379f487d807ea36bf9e06316fae6d20b706884b15b868fe8659e57cae94864aef9a704c799ab8221e13972553d8afa4bc0f4f1f5bd159e8f7e029125ac581d634fd8299e3a19f8ce0bdb5ae06db9549d562ac32658bb73cab7e0c1b628a6ab9977bdb87c5769becc5f22f306e66dd51644e13aacec3adb437147f2313a8cda96a7e2dc46e7cbb1349d0c8d1d375021142d153ea8c9f";
            var public_e = "010001";

            var decrtyed =  DecryptSignature(signature, public_N, public_e);
            Console.WriteLine(decrtyed);
        }

        static string DecryptSignature(string signature, string public_N, string public_e)
        {
            var sign = BigInteger.Parse(signature, NumberStyles.AllowHexSpecifier);
            var N = BigInteger.Parse(public_N, NumberStyles.AllowHexSpecifier);
            var e = BigInteger.Parse(public_e, NumberStyles.AllowHexSpecifier);
            // BigInteger exp = 65537;

            var res = BigInteger.ModPow(sign, e, N).ToString("x");
            return res;
        }

        static void RSAExample()
        {
            int plainData = 77;
            Console.WriteLine($"Plain data: {plainData}");

            int public_N = 3233, public_e = 17;
            int private_N = 3233, private_e = 2753;

            var encryptedData = BigInteger.ModPow(plainData, public_e, public_N);
            Console.WriteLine($"Encrypted data: {encryptedData}");

            var decryptedData = BigInteger.ModPow(encryptedData, private_e, private_N);
            Console.WriteLine($"Decrypted data: {decryptedData}");
        }
    }
}
