#ifndef MODBUSTCP_Modbus_H_
#define MODBUSTCP_Modbus_H_

#include <stdint.h>

#ifndef persist_
#define persist_ __attribute__((section(".persist")))
#endif
extern char persist_ ModbusTCP_Modbus_ip[16];
extern char persist_ ModbusTCP_Modbus_mac[18];
extern uint16_t persist_ ModbusTCP_Modbus_port;

void ModbusTCP_Modbus_init(void);

void ModbusTCP_Modbus_poll(void);




#endif

