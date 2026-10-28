using System;
using System.Collections.Generic;
using System.Text;

namespace KrbRelay.Clients
{
    /// <summary>
    /// Minimal KRB-AP-REQ inspector. A captured ticket is only usable against the service it was issued
    /// for, so knowing the sname before relaying (e.g. a cifs/ ticket presented to ldap/) turns a blind
    /// "bind refused" into a concrete diagnosis.
    /// </summary>
    public static class KerberosApReq
    {
        /// <summary>
        /// Extracts "service/host" and the realm from a captured token. The token may be a bare AP-REQ
        /// (tag 0x6e) or a SPNEGO NegTokenInit wrapping one, so the whole buffer is scanned for a valid
        /// AP-REQ structure (RFC 4120 uses explicit tags).
        /// </summary>
        public static bool TryGetServiceName(byte[] token, out string service, out string realm)
        {
            service = null;
            realm = null;
            if (token == null || token.Length < 16)
            {
                return false;
            }

            for (int i = 0; i < token.Length; i++)
            {
                if (token[i] != 0x6E) // [APPLICATION 14] AP-REQ
                {
                    continue;
                }
                if (TryParseApReq(token, i, out service, out realm))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Returns the bare AP-REQ ([APPLICATION 14]) contained in the token, unwrapping SPNEGO if present.
        /// Needed for servers that only accept the "GSSAPI" SASL mechanism instead of "GSS-SPNEGO".
        /// </summary>
        public static bool TryExtractApReq(byte[] token, out byte[] apReq)
        {
            apReq = null;
            if (token == null || token.Length < 16)
            {
                return false;
            }

            for (int i = 0; i < token.Length; i++)
            {
                if (token[i] != 0x6E)
                {
                    continue;
                }

                int end = i;
                if (!ReadTlv(token, ref end, out byte tag, out _, out _) || tag != 0x6E)
                {
                    continue;
                }
                if (!TryParseApReq(token, i, out _, out _))
                {
                    continue;
                }

                apReq = new byte[end - i];
                Buffer.BlockCopy(token, i, apReq, 0, apReq.Length);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Returns the GSS-API Kerberos token (0x60 ... Kerberos OID ... AP-REQ) contained in the buffer,
        /// i.e. what the SASL "GSSAPI" mechanism expects as credentials (the SPNEGO mechToken). A bare AP-REQ
        /// is NOT valid for that mechanism - Windows answers SEC_E_INVALID_TOKEN (0x80090308).
        /// </summary>
        public static bool TryExtractGssToken(byte[] token, out byte[] gssToken)
        {
            gssToken = null;
            if (token == null || token.Length < 32)
            {
                return false;
            }

            byte[] kerberosOid = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };

            for (int i = 0; i < token.Length; i++)
            {
                if (token[i] != 0x60)
                {
                    continue;
                }

                int end = i;
                if (!ReadTlv(token, ref end, out byte tag, out int contentOffset, out int contentLength) || tag != 0x60)
                {
                    continue;
                }

                // A GSS-API Kerberos token starts with 60 .. 06 09 <kerberos oid> .. <AP-REQ>.
                // The SPNEGO wrapper also contains that OID, but only deeper in (mechTypes), so require
                // the OID to be the FIRST element inside the token.
                int inner = contentOffset;
                if (!ReadTlv(token, ref inner, out byte oidTag, out int oidOffset, out int oidLength) || oidTag != 0x06)
                {
                    continue;
                }
                if (oidLength != kerberosOid.Length - 2)
                {
                    continue;
                }
                bool oidMatches = true;
                for (int j = 0; j < oidLength; j++)
                {
                    if (token[oidOffset + j] != kerberosOid[2 + j])
                    {
                        oidMatches = false;
                        break;
                    }
                }
                if (!oidMatches || !HasApReq(token, contentOffset, contentLength))
                {
                    continue;
                }

                gssToken = new byte[end - i];
                Buffer.BlockCopy(token, i, gssToken, 0, gssToken.Length);
                return true;
            }
            return false;
        }

        private static bool HasApReq(byte[] buffer, int offset, int length)
        {
            int end = offset + length;
            for (int i = offset; i < end; i++)
            {
                if (buffer[i] == 0x6E)
                {
                    return true;
                }
            }
            return false;
        }

        private static bool TryParseApReq(byte[] buffer, int start, out string service, out string realm)
        {
            service = null;
            realm = null;

            int offset = start;
            if (!ReadTlv(buffer, ref offset, out byte tag, out int apOffset, out int apLength) || tag != 0x6E)
            {
                return false;
            }

            int field = apOffset;
            int end = apOffset + apLength;

            // KRB-AP-REQ is encoded with explicit tags: 6e .. 30 .. <fields>
            if (field < end && buffer[field] == 0x30)
            {
                if (!ReadTlv(buffer, ref field, out byte seqTag, out int seqOffset, out int seqLength) || seqTag != 0x30)
                {
                    return false;
                }
                field = seqOffset;
                end = seqOffset + seqLength;
            }

            int ticketOffset = -1;
            int ticketLength = 0;
            while (field < end)
            {
                if (!ReadTlv(buffer, ref field, out byte fieldTag, out int fieldOffset, out int fieldLength))
                {
                    return false;
                }
                if (fieldTag == 0xA3) // [3] ticket
                {
                    ticketOffset = fieldOffset;
                    ticketLength = fieldLength;
                    break;
                }
            }
            if (ticketOffset < 0)
            {
                return false;
            }

            int ticket = ticketOffset;
            int ticketEnd = ticketOffset + ticketLength;

            // Ticket ::= [APPLICATION 1] SEQUENCE { ... }: real Windows tickets arrive as a3 -> 61 -> 30,
            // other stacks use a3 -> 30 (implicit) or a3 -> a0... (fully implicit). Unwrap up to two levels.
            for (int depth = 0; depth < 2 && ticket < ticketEnd; depth++)
            {
                byte nextTag = buffer[ticket];
                if (nextTag != 0x30 && nextTag != 0x61)
                {
                    break;
                }
                if (!ReadTlv(buffer, ref ticket, out byte tktTag, out int ticketInner, out int ticketInnerLength))
                {
                    return false;
                }
                if (tktTag != 0x30 && tktTag != 0x61)
                {
                    return false;
                }
                ticket = ticketInner;
                ticketEnd = ticketInner + ticketInnerLength;
            }

            string sname = null;
            while (ticket < ticketEnd)
            {
                if (!ReadTlv(buffer, ref ticket, out byte ticketFieldTag, out int ticketFieldOffset, out int ticketFieldLength))
                {
                    return false;
                }
                if (ticketFieldTag == 0xA1) // [1] realm
                {
                    realm = ReadString(buffer, ticketFieldOffset, ticketFieldLength);
                }
                else if (ticketFieldTag == 0xA2) // [2] sname
                {
                    sname = ReadPrincipalName(buffer, ticketFieldOffset, ticketFieldLength);
                }
            }

            if (string.IsNullOrEmpty(sname) || !IsPrintable(sname))
            {
                return false;
            }

            service = sname;
            return true;
        }

        private static string ReadPrincipalName(byte[] buffer, int offset, int length)
        {
            int field = offset;
            int end = offset + length;

            if (field < end && buffer[field] == 0x30)
            {
                if (!ReadTlv(buffer, ref field, out byte seqTag, out int seqOffset, out int seqLength) || seqTag != 0x30)
                {
                    return null;
                }
                field = seqOffset;
                end = seqOffset + seqLength;
            }

            while (field < end)
            {
                if (!ReadTlv(buffer, ref field, out byte tag, out int valueOffset, out int valueLength))
                {
                    return null;
                }
                if (tag != 0xA1) // [1] name-string
                {
                    continue;
                }

                int item = valueOffset;
                int itemEnd = valueOffset + valueLength;
                if (item < itemEnd && buffer[item] == 0x30)
                {
                    if (!ReadTlv(buffer, ref item, out byte listTag, out int listOffset, out int listLength) || listTag != 0x30)
                    {
                        return null;
                    }
                    item = listOffset;
                    itemEnd = listOffset + listLength;
                }

                List<string> parts = new List<string>();
                while (item < itemEnd)
                {
                    if (!ReadTlv(buffer, ref item, out byte partTag, out int partOffset, out int partLength))
                    {
                        return null;
                    }
                    string part = ReadString(buffer, partOffset, partLength);
                    if (!string.IsNullOrEmpty(part))
                    {
                        parts.Add(part);
                    }
                }
                return parts.Count > 0 ? string.Join("/", parts) : null;
            }
            return null;
        }

        private static string ReadString(byte[] buffer, int offset, int length)
        {
            int field = offset;
            int end = offset + length;
            if (field < end && (buffer[field] == 0x1B || buffer[field] == 0x04 || buffer[field] == 0x0C))
            {
                if (!ReadTlv(buffer, ref field, out byte tag, out int valueOffset, out int valueLength))
                {
                    return null;
                }
                return Encoding.UTF8.GetString(buffer, valueOffset, valueLength);
            }
            return Encoding.UTF8.GetString(buffer, offset, length);
        }

        private static bool IsPrintable(string value)
        {
            if (value.Length == 0 || value.Length > 256)
            {
                return false;
            }
            foreach (char c in value)
            {
                if (c < 0x20 || c > 0x7E)
                {
                    return false;
                }
            }
            return true;
        }

        private static bool ReadTlv(byte[] buffer, ref int offset, out byte tag, out int valueOffset, out int length)
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
                if (count == 0 || count > 4 || offset + count > buffer.Length)
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
    }
}
