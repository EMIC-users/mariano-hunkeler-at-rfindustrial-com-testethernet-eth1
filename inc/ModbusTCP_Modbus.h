#ifndef MODBUSTCP_Modbus_H_
#define MODBUSTCP_Modbus_H_

#include <stdint.h>

void ModbusTCP_Modbus_init(void);

void ModbusTCP_Modbus_poll(void);

void ModbusTCP_Modbus_setReg(uint8_t addr, uint16_t value);


extern void ModbusTCP_Modbus_onRegWritten(uint8_t addr, uint16_t value);

#endif

