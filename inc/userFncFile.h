#ifndef USERFNCFILE_H
#define USERFNCFILE_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

// includes type definitions

/* Function Prototypes */
void onReset();
void ModbusTCP_Modbus_onRegWritten(uint8_t addr, uint16_t value);
void ModbusTCP_Modbus_onMotorStart1(uint16_t value);

#endif /* USERFNCFILE_H */

