#pragma once

void UART_InitReceiveRingBuffer(int size);
int UART_GetDataSize();
byte UART_GetByte(int idx);
void UART_ConsumeBytes(int idx);
void UART_AppendByteToReceiveRingBuffer(int rc);
void UART_SendByte(byte b);
int UART_InitUART(int baud, int parity);
void UART_AddCommands();
void UART_RunEverySecond();

// used to detect uart reinit/takeover by driver
int get_g_uart_init_counter();

int UART_GetSelectedPortIndex();


//new with uart selection
void UART_InitReceiveRingBufferEx(int auartindex, int size);
int UART_GetDataSizeEx(int auartindex);
byte UART_GetByteEx(int auartindex, int idx);
void UART_ConsumeBytesEx(int auartindex, int idx);
void UART_SendByteEx(int auartindex, byte b);
int UART_InitUARTEx(int auartindex, int baud, int parity);
void UART_LogBufState(int auartindex);

//index of UART port 
#define UART_PORT_INDEX_0 0
#define UART_PORT_INDEX_1 1
