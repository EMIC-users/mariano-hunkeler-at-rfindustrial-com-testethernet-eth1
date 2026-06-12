#ifndef MODBUSTCP_Modbus_H_
#define MODBUSTCP_Modbus_H_

#include <stdint.h>

#ifndef persist_
#define _PERSIST_STR2(x) #x
#define _PERSIST_STR(x) _PERSIST_STR2(x)
#define persist_ __attribute__((section(".persist." _PERSIST_STR(__COUNTER__))))
#endif
extern char ModbusTCP_Modbus_ip[16];
extern char ModbusTCP_Modbus_mac[18];
extern uint16_t ModbusTCP_Modbus_port;

void ModbusTCP_Modbus_init(void);

void ModbusTCP_Modbus_poll(void);




#endif

