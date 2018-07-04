#include <arpa/inet.h>

#include "legato.h"
#include "interfaces.h"

#define u8 unsigned char
#define u16 unsigned short
//#define SERVER_ADDR "103.29.161.24"
#define SERVER_ADDR "115.64.223.162"
#define BUFFER_SIZE 1024

static le_data_RequestObjRef_t RequestRef = NULL;

// -------------------------------------------------------------------------------------------------
/**
 *  Get a string for a given network state enumeration.
 *
 *  @return
 *       A string that best represents the given enumerated network state.
 *
 *  @note
 *       Do *not* free the returned string.
 */
// -------------------------------------------------------------------------------------------------
static const char* GetNetStateString
(
    le_mrc_NetRegState_t state   ///< [IN] Network state to translate into a string.
)
{
    char* string = NULL;

    switch (state)
    {
        case LE_MRC_REG_NONE:
            string = "off of the network";
            break;

        case LE_MRC_REG_HOME:
            string = "registered on its home network";
            break;

        case LE_MRC_REG_SEARCHING:
            string = "searching for network";
            break;

        case LE_MRC_REG_DENIED:
            string = "denied access to the network";
            break;

        case LE_MRC_REG_ROAMING:
            string = "registered on a roaming network";
            break;

        case LE_MRC_REG_UNKNOWN:
        default:
            string = "in an unknown state";
            break;
    }

    return string;
}

// -------------------------------------------------------------------------------------------------
/**
 *  An event callback that is run every time the modem's state changes.  When the modem becomes
 *  attached to a network, a message is sent to a preconfigured target.  However the target and the
 *  message to be send have to be passed on program startup.
 */
// -------------------------------------------------------------------------------------------------
static void NetRegStateHandler
(
    le_mrc_NetRegState_t state,   ///< [IN] The new state of the modem.
    void*                contextPtr
)
{
    // Record the change of state to the chat log.
//    if (OutputFilePtr)
//    {
//        fprintf(OutputFilePtr, "## %s ##\n", GetNetStateString(state));
//        fflush(OutputFilePtr);
//    }

    // For traceablity, make sure that this event is recorded.
    LE_DEBUG("Jazz: Network status changed!! %s", GetNetStateString(state));

    // If we are going back on net, and have been configured to do so, send our "on network" message
    // now.
//    if ((state == LE_MRC_REG_HOME) || (state == LE_MRC_REG_ROAMING))
//    {
//        LE_DEBUG("Sending On Network Message.");
//        //SendMessage(DestNum, "Getting back on network.");
//    }
}

static const u16 crctab16[] =
{
0X0000, 0X1189, 0X2312, 0X329B, 0X4624, 0X57AD, 0X6536, 0X74BF,
0X8C48, 0X9DC1, 0XAF5A, 0XBED3, 0XCA6C, 0XDBE5, 0XE97E, 0XF8F7,
0X1081, 0X0108, 0X3393, 0X221A, 0X56A5, 0X472C, 0X75B7, 0X643E,
0X9CC9, 0X8D40, 0XBFDB, 0XAE52, 0XDAED, 0XCB64, 0XF9FF, 0XE876,
0X2102, 0X308B, 0X0210, 0X1399, 0X6726, 0X76AF, 0X4434, 0X55BD,
0XAD4A, 0XBCC3, 0X8E58, 0X9FD1, 0XEB6E, 0XFAE7, 0XC87C, 0XD9F5,
0X3183, 0X200A, 0X1291, 0X0318, 0X77A7, 0X662E, 0X54B5, 0X453C,
0XBDCB, 0XAC42, 0X9ED9, 0X8F50, 0XFBEF, 0XEA66, 0XD8FD, 0XC974,
0X4204, 0X538D, 0X6116, 0X709F, 0X0420, 0X15A9, 0X2732, 0X36BB,
0XCE4C, 0XDFC5, 0XED5E, 0XFCD7, 0X8868, 0X99E1, 0XAB7A, 0XBAF3,
0X5285, 0X430C, 0X7197, 0X601E, 0X14A1, 0X0528, 0X37B3, 0X263A,
0XDECD, 0XCF44, 0XFDDF, 0XEC56, 0X98E9, 0X8960, 0XBBFB, 0XAA72,
0X6306, 0X728F, 0X4014, 0X519D, 0X2522, 0X34AB, 0X0630, 0X17B9,
0XEF4E, 0XFEC7, 0XCC5C, 0XDDD5, 0XA96A, 0XB8E3, 0X8A78, 0X9BF1,
0X7387, 0X620E, 0X5095, 0X411C, 0X35A3, 0X242A, 0X16B1, 0X0738,
0XFFCF, 0XEE46, 0XDCDD, 0XCD54, 0XB9EB, 0XA862, 0X9AF9, 0X8B70,
0X8408, 0X9581, 0XA71A, 0XB693, 0XC22C, 0XD3A5, 0XE13E, 0XF0B7,
0X0840, 0X19C9, 0X2B52, 0X3ADB, 0X4E64, 0X5FED, 0X6D76, 0X7CFF,
0X9489, 0X8500, 0XB79B, 0XA612, 0XD2AD, 0XC324, 0XF1BF, 0XE036,
0X18C1, 0X0948, 0X3BD3, 0X2A5A, 0X5EE5, 0X4F6C, 0X7DF7, 0X6C7E,
0XA50A, 0XB483, 0X8618, 0X9791, 0XE32E, 0XF2A7, 0XC03C, 0XD1B5,
0X2942, 0X38CB, 0X0A50, 0X1BD9, 0X6F66, 0X7EEF, 0X4C74, 0X5DFD,
0XB58B, 0XA402, 0X9699, 0X8710, 0XF3AF, 0XE226, 0XD0BD, 0XC134,
0X39C3, 0X284A, 0X1AD1, 0X0B58, 0X7FE7, 0X6E6E, 0X5CF5, 0X4D7C,
0XC60C, 0XD785, 0XE51E, 0XF497, 0X8028, 0X91A1, 0XA33A, 0XB2B3,
0X4A44, 0X5BCD, 0X6956, 0X78DF, 0X0C60, 0X1DE9, 0X2F72, 0X3EFB,
0XD68D, 0XC704, 0XF59F, 0XE416, 0X90A9, 0X8120, 0XB3BB, 0XA232,
0X5AC5, 0X4B4C, 0X79D7, 0X685E, 0X1CE1, 0X0D68, 0X3FF3, 0X2E7A,
0XE70E, 0XF687, 0XC41C, 0XD595, 0XA12A, 0XB0A3, 0X8238, 0X93B1,
0X6B46, 0X7ACF, 0X4854, 0X59DD, 0X2D62, 0X3CEB, 0X0E70, 0X1FF9,
0XF78F, 0XE606, 0XD49D, 0XC514, 0XB1AB, 0XA022, 0X92B9, 0X8330,
0X7BC7, 0X6A4E, 0X58D5, 0X495C, 0X3DE3, 0X2C6A, 0X1EF1, 0X0F78,
};

u16 GetCrc16(u8* pData, int nLength)
{
u16 fcs = 0xffff;
while(nLength>0){
fcs = (fcs >> 8) ^ crctab16[(fcs ^ *pData) & 0xff];
nLength--;
pData++;
}
return ~fcs;
}

void str2num(char* string_in, int length, u8* numArray)
{


    for (int i = 0; i < length/2; i++)
    {
        char twoBit[2];
        char *ptr;
        //Fetch 2 bits from the string in
        strncpy(twoBit, string_in + i * 2, 2);

        //convert the two bits into integer
        numArray[i] = (int)strtol(twoBit, &ptr, 16);
    }
    return;
}

COMPONENT_INIT
{
	le_result_t result;
	le_onoff_t power;
	char buffer[1024] = {0};


	LE_INFO("Jazz's Program Started");
	unsigned char loginPacket[18] = {0};
	u16 numSequence; // sequence number in packet.

	loginPacket[0] = 0x78;
	loginPacket[1] = 0x78;
	loginPacket[2] = 0x0d;
	loginPacket[3] = 0x01;

	char *serialNumber = "0865851038000010"; //Serial Number of this device
	int lenSerialNumber = strlen(serialNumber);
	u8 *numSerialNumberArray = (u8 *)malloc(lenSerialNumber/2);
	str2num(serialNumber, lenSerialNumber, numSerialNumberArray);
	for (int i=0 ; i < lenSerialNumber/2 ; i++)
		//LE_INFO("Serial Number: %x", numSerialNumberArray[i]);
		loginPacket[4+i] = numSerialNumberArray[i];

	numSequence = 0x0001;
	loginPacket[12] = numSequence>>8; //high 8 bit of numSequence
	loginPacket[13] = numSequence&0xFF; //low 8 bit of numSequence

	//Now calculate the checksum
	u8 *pLoginPacket;
	pLoginPacket = loginPacket;
	u16 crcResult = GetCrc16(pLoginPacket+2, 12);

	loginPacket[14] = crcResult>>8; //high 8 bit of crc result
	loginPacket[15] = crcResult&0xFF; //low 8 bit of crc result

	loginPacket[16] = 0x0d;
	loginPacket[17] = 0x0a;

	for (int i=0; i<16 ; i++)
		LE_INFO("Login Packet: %x", loginPacket[i]);

	free(numSerialNumberArray);


    // register network state handler
    le_mrc_AddNetRegStateEventHandler(NetRegStateHandler, NULL);

    // Now, make sure that the radio has been turned on and is ready to go.
    if ((result = le_mrc_GetRadioPower(&power)) != LE_OK)
    {
        LE_WARN("Failed to get the radio power.  Result: %d", result);
    }
    else if (power == LE_OFF)
    {
        if ((result = le_mrc_SetRadioPower(LE_ON)) != LE_OK)
        {
            LE_FATAL("Failed to set the radio power.  Result: %d", result);
        }
    }

    // Request the data connection, only after this can we start send and receive data.
	if(RequestRef)
	    {
	        LE_ERROR("A connection request already exist.");
	        return;
	    }

	RequestRef = le_data_Request();
	LE_INFO("Requesting the default data connection: %p.", RequestRef);

	sleep(5);//Wait for 5 seconds, so the data connection is ready

	//char* loginString;
	char* recvBuffer={"0"};
	int sockFd = 0;
	struct sockaddr_in servAddr;

	//Setting everything in this structure to zero
	memset(&servAddr, 0, sizeof(servAddr));

	if ((sockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		snprintf(buffer, 1024, "Failed to create socket");
		return;
	}

	LE_INFO("Connecting to %s (BK server)\n", SERVER_ADDR);

	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(8888);
	servAddr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

	if (connect(sockFd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		LE_INFO("Connection to BK Server failed.");
		snprintf(buffer, BUFFER_SIZE,
				"Failed to connect to BK server.");

	} else {
		LE_INFO("Connection Successful");
		snprintf(buffer, BUFFER_SIZE,
				"Connection to www.sierrawireless.com was successful.");

		send(sockFd, loginPacket, 7, 0);
		recv(sockFd, recvBuffer, 30, 0);
		LE_INFO("Received reply\n");
	}

	close(sockFd);


	// Release RequestRef
	if(!RequestRef)
	    {
	        LE_ERROR("Not existing connection reference.");
	        return;
	    }

	le_data_Release(RequestRef);
	LE_INFO("Releasing the default data connection.");

	RequestRef = NULL;

    LE_INFO("Hello, world.");
}
