
namespace SMBLibrary
{
    public enum NTStatus : uint
    {
        STATUS_SUCCESS = 0x00000000,
        STATUS_PENDING = 0x00000103,
        STATUS_NOTIFY_CLEANUP = 0x0000010B,
        STATUS_NOTIFY_ENUM_DIR = 0x0000010C,
        SEC_I_CONTINUE_NEEDED = 0x00090312,
        STATUS_OBJECT_NAME_EXISTS = 0x40000000,
        STATUS_BUFFER_OVERFLOW = 0x80000005,
        STATUS_NO_MORE_FILES = 0x80000006,
        SEC_E_SECPKG_NOT_FOUND = 0x80090305,
        SEC_E_INVALID_TOKEN = 0x80090308,
        STATUS_NOT_IMPLEMENTED = 0xC0000002,
        STATUS_INVALID_INFO_CLASS = 0xC0000003,
        STATUS_INFO_LENGTH_MISMATCH = 0xC0000004,
        STATUS_INVALID_HANDLE = 0xC0000008,
        STATUS_INVALID_PARAMETER = 0xC000000D,
        STATUS_NO_SUCH_DEVICE = 0xC000000E,
        STATUS_NO_SUCH_FILE = 0xC000000F,
        STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
        STATUS_END_OF_FILE = 0xC0000011,
        STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
        STATUS_ACCESS_DENIED = 0xC0000022, // The user is not authorized to access the resource.
        STATUS_BUFFER_TOO_SMALL = 0xC0000023,
        STATUS_OBJECT_NAME_INVALID = 0xC0000033,
        STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
        STATUS_OBJECT_NAME_COLLISION = 0xC0000035, // The file already exists
        STATUS_OBJECT_PATH_INVALID = 0xC0000039,
        STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A, // The share path does not reference a valid resource.
        STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
        STATUS_DATA_ERROR = 0xC000003E, // IO error
        STATUS_SHARING_VIOLATION = 0xC0000043,
        STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
        STATUS_LOCK_NOT_GRANTED = 0xC0000055,
        STATUS_DELETE_PENDING = 0xC0000056,
        STATUS_IO_TIMEOUT = 0xC00000B5,
        STATUS_PRIVILEGE_NOT_HELD = 0xC0000061,
        STATUS_WRONG_PASSWORD = 0xC000006A,
        STATUS_LOGON_FAILURE = 0xC000006D, // Authentication failure.
        STATUS_ACCOUNT_RESTRICTION = 0xC000006E, // The user has an empty password, which is not allowed
        STATUS_INVALID_LOGON_HOURS = 0xC000006F,
        STATUS_INVALID_WORKSTATION = 0xC0000070,
        STATUS_PASSWORD_EXPIRED = 0xC0000071,
        STATUS_ACCOUNT_DISABLED = 0xC0000072,
        STATUS_RANGE_NOT_LOCKED = 0xC000007E,
        STATUS_DISK_FULL = 0xC000007F,
        STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
        STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2,
        STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
        STATUS_NOT_SUPPORTED = 0xC00000BB,
        STATUS_NETWORK_NAME_DELETED = 0xC00000C9,
        STATUS_BAD_DEVICE_TYPE = 0xC00000CB,
        STATUS_BAD_NETWORK_NAME = 0xC00000CC,
        STATUS_TOO_MANY_SESSIONS = 0xC00000CE,
        STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0,
        STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101,
        STATUS_NOT_A_DIRECTORY = 0xC0000103,
        STATUS_TOO_MANY_OPENED_FILES = 0xC000011F,
        STATUS_CANCELLED = 0xC0000120,
        STATUS_CANNOT_DELETE = 0xC0000121,
        STATUS_FILE_CLOSED = 0xC0000128,
        STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000015B,
        STATUS_ACCOUNT_EXPIRED = 0xC0000193,
        STATUS_FS_DRIVER_REQUIRED = 0xC000019C,
        STATUS_USER_SESSION_DELETED = 0xC0000203,
        STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205,
        STATUS_PASSWORD_MUST_CHANGE = 0xC0000224,
        STATUS_NOT_FOUND = 0xC0000225,
        STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234,
        STATUS_PATH_NOT_COVERED = 0xC0000257,
        STATUS_NOT_A_REPARSE_POINT = 0xC0000275,

        STATUS_INVALID_SMB = 0x00010002,        // SMB1/CIFS: A corrupt or invalid SMB request was received
        STATUS_SMB_BAD_COMMAND = 0x00160002,    // SMB1/CIFS: An unknown SMB command code was received by the server
        STATUS_SMB_BAD_FID = 0x00060001,        // SMB1/CIFS
        STATUS_SMB_BAD_TID = 0x00050002,        // SMB1/CIFS
        STATUS_OS2_INVALID_ACCESS = 0x000C0001, // SMB1/CIFS
        STATUS_OS2_NO_MORE_SIDS = 0x00710001,   // SMB1/CIFS
        STATUS_OS2_INVALID_LEVEL = 0x007C0001,  // SMB1/CIFS
    }
}
