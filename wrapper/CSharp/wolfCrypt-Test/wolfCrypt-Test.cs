/* wolfCrypt-Test.cs
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Tests for the wolfCrypt C# wrapper */

using System;
using System.Linq;
using System.Security.Cryptography;
using wolfSSL.CSharp;

public class wolfCrypt_Test_CSharp
{
    private static void random_test()
    {
        int ret, i, zeroCount = 0;
        Byte[] data = new Byte[128];

        /* Random Test */
        ret = wolfcrypt.Random(data, data.Length);
        if (ret == 0)
        {
            /* Check for 0's */
            for (i = 0; i < (int)data.Length; i++)
            {
                if (data[i] == 0)
                {
                    zeroCount++;
                }
            }
            if (zeroCount == data.Length)
            {
                Console.WriteLine("RNG zero check error");
            }
            else
            {
                Console.WriteLine("RNG Test Passed\n");
            }
        }
        else
        {
            Console.WriteLine("RNG Error" + wolfcrypt.GetError(ret));
        }
    } /* END random_test */

    private static void ecc_test(string hashAlgorithm, int keySize)
    {
        IntPtr PrivKey = IntPtr.Zero;
        IntPtr PubKey = IntPtr.Zero;
        IntPtr key = IntPtr.Zero;

        try
        {
            Console.WriteLine("Starting ECC tests...");

            /* Generate ECC Key Pair */
            Console.WriteLine("Testing ECC Key Generation...");
            key = wolfcrypt.EccMakeKey(keySize);
            if (key == IntPtr.Zero)
            {
                throw new Exception("EccMakeKey failed");
            }
            Console.WriteLine("ECC Key Generation test passed.");

            /* Export and Import Key */
            Console.WriteLine("Testing ECC Key Export and Import...");
            byte[] privateKeyDer = wolfcrypt.ExportPrivateKeyToDer(key);
            byte[] publicKeyDer = wolfcrypt.ExportPublicKeyToDer(key, true);

            PrivKey = wolfcrypt.EccImportKey(privateKeyDer);
            if (PrivKey == IntPtr.Zero)
            {
                throw new Exception("EccImportKey Private failed");
            }

            PubKey = wolfcrypt.ImportPublicKeyFromDer(publicKeyDer);
            if (PubKey == IntPtr.Zero)
            {
                throw new Exception("ImportPublicKeyFromDer Public failed");
            }

            Console.WriteLine("ECC Key Export and Import test passed.");

            /* Generate hash based on selected algorithm */
            byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");
            byte[] hash;

            switch (hashAlgorithm.ToUpper())
            {
                case "SHA256":
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(dataToHash);
                    }
                    break;

                case "SHA384":
                    using (SHA384 sha384 = SHA384.Create())
                    {
                        hash = sha384.ComputeHash(dataToHash);
                    }
                    break;

                case "SHA512":
                    using (SHA512 sha512 = SHA512.Create())
                    {
                        hash = sha512.ComputeHash(dataToHash);
                    }
                    break;

                default:
                    throw new Exception("Unsupported hash algorithm");
            }

            Console.WriteLine($"{hashAlgorithm} hash generated.");

            /* Sign Data */
            Console.WriteLine("Testing ECC Signature Creation...");
            byte[] signature = new byte[wolfcrypt.ECC_MAX_SIG_SIZE];
            int signLength = wolfcrypt.EccSign(PrivKey, hash, signature);
            if (signLength <= 0)
            {
                    throw new Exception("EccSign failed");
            }

            byte[] actualSignature = new byte[signLength];
            Array.Copy(signature, 0, actualSignature, 0, signLength);

            Console.WriteLine($"ECC Signature Creation test passed. Signature Length: {signLength}");

            /* Verify Signature */
            Console.WriteLine("Testing ECC Signature Verification...");
            int verifyResult = wolfcrypt.EccVerify(PubKey, actualSignature, hash);
            if (verifyResult != 0)
            {
                throw new Exception("EccVerify failed");
            }
            Console.WriteLine("ECC Signature Verification test passed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ECC test failed: {ex.Message}");
        }
        finally
        {
            /* Cleanup */
            if (key != IntPtr.Zero) wolfcrypt.EccFreeKey(key);
            if (PubKey != IntPtr.Zero) wolfcrypt.EccFreeKey(PubKey);
            if (PrivKey != IntPtr.Zero) wolfcrypt.EccFreeKey(PrivKey);
        }
        Console.WriteLine("ECC test completed successfully.\n");
    } /* END ecc_test */

    private static void rsa_test(string hashAlgorithm, int keySize)
    {
        IntPtr key = IntPtr.Zero;

        try
        {
            Console.WriteLine("Starting RSA tests...");

            IntPtr heap = IntPtr.Zero;
            int devId = wolfcrypt.INVALID_DEVID;

            /* Generate RSA Key Pair */
            Console.WriteLine("Testing RSA Key Generation...");
            key = wolfcrypt.RsaMakeKey(heap, devId, keySize);
            if (key == IntPtr.Zero)
            {
                throw new Exception("RsaMakeKey failed");
            }
            Console.WriteLine("RSA Key Generation test passed.");

            /* Generate hash based on selected algorithm */
            byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");
            byte[] hash;

            switch (hashAlgorithm.ToUpper())
            {
                case "SHA256":
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(dataToHash);
                    }
                    break;

                case "SHA384":
                    using (SHA384 sha384 = SHA384.Create())
                    {
                        hash = sha384.ComputeHash(dataToHash);
                    }
                    break;

                case "SHA512":
                    using (SHA512 sha512 = SHA512.Create())
                    {
                        hash = sha512.ComputeHash(dataToHash);
                    }
                    break;

                default:
                    throw new Exception("Unsupported hash algorithm");
            }

            Console.WriteLine($"{hashAlgorithm} hash generated.");

            /* Sign Data */
            Console.WriteLine("Testing RSA Signature Creation...");
            byte[] signature = new byte[keySize / 8];
            int signLength = wolfcrypt.RsaSignSSL(key, hash, signature);
            if (signLength <= 0)
            {
                throw new Exception("RsaSignSSL failed");
            }

            byte[] actualSignature = new byte[signLength];
            Array.Copy(signature, 0, actualSignature, 0, signLength);

            Console.WriteLine($"RSA Signature Creation test passed. Signature Length: {signLength}");

            /* Verify Signature */
            Console.WriteLine("Testing RSA Signature Verification...");
            int verifyResult = wolfcrypt.RsaVerifySSL(key, actualSignature, hash);
            if (verifyResult != 0)
            {
                throw new Exception("RsaVerifySSL failed");
            }
            Console.WriteLine("RSA Signature Verification test passed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"RSA test failed: {ex.Message}");
        }
        finally
        {
            /* Cleanup */
            if (key != IntPtr.Zero) wolfcrypt.RsaFreeKey(key);
        }
        Console.WriteLine("RSA test completed successfully.\n");
    } /* END rsa_test */

    private static void ed25519_test()
    {
        IntPtr key = IntPtr.Zero;
        byte[] privKey;
        byte[] pubKey;
        int ret;

        try
        {
            Console.WriteLine("Starting ED25519 tests...");

            IntPtr heap = IntPtr.Zero;
            int devId = wolfcrypt.INVALID_DEVID;

            /* Generate ED25519 Key Pair */
            Console.WriteLine("Testing ED25519 Key Generation...");
            key = wolfcrypt.Ed25519MakeKey(heap, devId);
            if (key == IntPtr.Zero)
            {
                throw new Exception("Ed25519MakeKey failed");
            }

            Console.WriteLine("ED25519 Key Generation test passed.");

            /* Export and Import Key */
            Console.WriteLine("Testing ED25519 Key Export and Import...");
            /* Export Private */
            int privateKeyDer = wolfcrypt.Ed25519ExportKeyToDer(key, out privKey);
            if (key == IntPtr.Zero || privKey == null)
            {
                throw new Exception("Ed25519ExportKeyToDer failed");
            }
            /* Export Public */
            int publicKeyDer = wolfcrypt.Ed25519ExportPublicKeyToDer(key, out pubKey, true);
            if (key == IntPtr.Zero || pubKey == null)
            {
                throw new Exception("Ed25519ExportKeyToDer failed");
            }
            /* Import Private */
            IntPtr importedPrivKey = wolfcrypt.Ed25519PrivateKeyDecode(privKey);
            if (importedPrivKey == IntPtr.Zero)
            {
                throw new Exception("Ed25519PrivateKeyDecode failed");
            }
            /* Import Public */
            IntPtr importedPubKey = wolfcrypt.Ed25519PublicKeyDecode(pubKey);
            if (importedPubKey == IntPtr.Zero)
            {
                throw new Exception("Ed25519PublicKeyDecode failed");
            }

            Console.WriteLine("ED25519 Key Export and Import test passed.");

            /* Generate a hash */
            byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");

            /* Sign Data */
            Console.WriteLine("Testing ED25519 Signature Creation...");
            byte[] signature;

            ret = wolfcrypt.Ed25519SignMsg(dataToHash, out signature, key);
            if (ret != 0)
            {
                throw new Exception("Ed25519SignMsg failed");
            }

            Console.WriteLine($"ED25519 Signature Creation test passed. Signature Length: {signature.Length}");

            /* Verify Signature */
            Console.WriteLine("Testing ED25519 Signature Verification...");
            ret = wolfcrypt.Ed25519VerifyMsg(signature, dataToHash, key);
            if (ret != 0)
            {
                throw new Exception("Ed25519VerifyMsg failed");
            }
            Console.WriteLine("ED25519 Signature Verification test passed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ED25519 test failed: {ex.Message}");
        }
        finally
        {
            /* Cleanup */
            if (key != IntPtr.Zero) wolfcrypt.Ed25519FreeKey(key);           
        }
        Console.WriteLine("ED25519 test completed successfully.\n");
    } /* END ed25519_test */

    private static void curve25519_test()
    {
        IntPtr keyA = IntPtr.Zero;
        IntPtr keyB = IntPtr.Zero;
        IntPtr publicKeyA = IntPtr.Zero;
        IntPtr publicKeyB = IntPtr.Zero;
        byte[] derKey;

        try
        {
            Console.WriteLine("Starting Curve25519 test...");

            /* Generate Key Pair A */
            Console.WriteLine("Generating Key Pair A...");
            keyA = wolfcrypt.Curve25519MakeKey(IntPtr.Zero, 0);
            if (keyA == IntPtr.Zero)
            {
                throw new Exception("Failed to generate key pair A.");
            }

            /*  Generate Key Pair B */
            Console.WriteLine("Generating Key Pair B...");
            keyB = wolfcrypt.Curve25519MakeKey(IntPtr.Zero, 0);
            if (keyB == IntPtr.Zero)
            {
                throw new Exception("Failed to generate key pair B.");
            }
            Console.WriteLine("Curve25519 Key generation test passed.");

            /* Export Public Key B to DER format */
            Console.WriteLine("Exporting Public Key B to DER format...");
            int publicKeyBDer = wolfcrypt.Curve25519ExportPublicKeyToDer(keyB, out derKey, true);

            /* Decode Public Key B from DER format */
            Console.WriteLine("Decoding Public Key B from DER format...");
            publicKeyB = wolfcrypt.Curve25519PublicKeyDecode(derKey);
            if (publicKeyB == IntPtr.Zero)
            {
                throw new Exception("Failed to decode public key B from DER format.");
            }
            Console.WriteLine("Curve25519 Export and Import test passed.");

            /* Compute Shared Secret using Private Key A and Public Key B */
            Console.WriteLine("Computing Shared Secret using Private Key A and Public Key B...");
            byte[] sharedSecretA = new byte[wolfcrypt.ED25519_KEY_SIZE];
            int retA = wolfcrypt.Curve25519SharedSecret(keyA, publicKeyB, sharedSecretA);
            if (retA != 0)
            {
                throw new Exception("Failed to compute shared secret A. Error code: " + retA);
            }
            Console.WriteLine("Curve25519 shared sercret created using private Key A.");

            /* Export Public Key A to DER format */
            Console.WriteLine("Exporting Public Key A to DER format...");
            int publicKeyADer = wolfcrypt.Curve25519ExportPublicKeyToDer(keyA, out derKey, true);

            /* Decode Public Key A from DER format */
            Console.WriteLine("Decoding Public Key A from DER format...");
            publicKeyA = wolfcrypt.Curve25519PublicKeyDecode(derKey);
            if (publicKeyA == IntPtr.Zero)
            {
                throw new Exception("Failed to decode public key A from DER format.");
            }

            /* Compute Shared Secret using Private Key B and Public Key A */
            Console.WriteLine("Computing Shared Secret using Private Key B and Public Key A...");
            byte[] sharedSecretB = new byte[wolfcrypt.ED25519_KEY_SIZE];
            int retB = wolfcrypt.Curve25519SharedSecret(keyB, publicKeyA, sharedSecretB);
            if (retB != 0)
            {
                throw new Exception("Failed to compute shared secret B. Error code: " + retB);
            }
            Console.WriteLine("Curve25519 shared sercret created using private Key B.");

            /* Compare Shared Secrets */
            Console.WriteLine("Comparing Shared Secrets...");
            if (!wolfcrypt.ByteArrayVerify(sharedSecretA, sharedSecretB))
            {
                throw new Exception("Shared secrets do not match.");
            }
            else
            {
                Console.WriteLine("Curve25519 shared sercret match.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Curve25519 test failed: {ex.Message}");
        }
        finally
        {
            /* Cleanup */
            if (keyA != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(keyA);
            if (keyB != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(keyB);
            if (publicKeyA != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(publicKeyA);
            if (publicKeyB != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(publicKeyB);
        }
        Console.WriteLine("Curve25519 test completed successfully.\n");
    } /* END curve25519_test */

    public static void Main(string[] args)
    {
        try
        {
            Console.WriteLine("Starting Cryptographic Tests...\n");

            wolfcrypt.Init();

            random_test();

            ecc_test("SHA256", 32); /* Uses SHA-256 (32 byte hash) */
            ecc_test("SHA384", 32); /* Uses SHA-384 (32 byte hash) */
            ecc_test("SHA512", 32); /* Uses SHA-512 (32 byte hash) */

            rsa_test("SHA256", 2048); /* Uses SHA-256 (2048 bit hash) */
            rsa_test("SHA384", 2048); /* Uses SHA-384 (2048 bit hash) */
            rsa_test("SHA512", 2048); /* Uses SHA-512 (2048 bit hash) */

            ed25519_test(); /* ED25519 test */

            curve25519_test(); /* curve25519 test */

            wolfcrypt.Cleanup();

            Console.WriteLine("All tests completed successfully.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }
}
