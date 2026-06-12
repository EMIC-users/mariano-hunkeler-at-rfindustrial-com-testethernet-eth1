#include <xc.h>
#include "inc/systemConfig.h"

#include "inc/systemTimer.h"
#include "inc/led_Led1.h"
#include "inc/ModbusTCP_Modbus.h"
#include "inc/Persist.h"
#include "inc/conversionFunctions.h"
#include "inc/system.h"
#include "inc/userFncFile.h"

#include "system.c"

int main(void)
{
	initSystem();
	systemTimeInit();
	LEDs_Led1_init();
	ModbusTCP_Modbus_init();
	onReset();
	do
	{
		ModbusTCP_Modbus_poll();
	}
	while(1);
}

