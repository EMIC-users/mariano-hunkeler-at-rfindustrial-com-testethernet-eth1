#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "inc/userFncFile.h"
#include "inc/systemTimer.h"
#include "inc/led_Led1.h"
#include "inc/ModbusTCP_Modbus.h"
#include "inc/conversionFunctions.h"

/* User Variables */
float Temp;
int16_t miVar;
int32_t counr;

void onReset()
{
    LEDs_Led1_state(1);
}


void ModbusTCP_Modbus_onRegWritten(uint8_t addr, uint16_t value)
{
    LEDs_Led1_state(2);
    ModbusTCP_Modbus_setReg(19, value);
}


/* Modbus map 'Modbus' (api ModbusTCP): 1 bindings -> SYS:/modbusMap.emic */



