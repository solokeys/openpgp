/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include "openpgplib.h"
#include "opgpdevice.h"
#include "solofactory.h"
#include "applets/apduconst.h"

#include "device.h"

// result buffer
PUT_TO_SRAM2 static uint8_t apdu_result[4096] = {0};

bool DoReset = false;

Applet::APDUExecutor *fexecutor = nullptr;
OpenPGP::Security *fsecurity = nullptr;
void OpenpgpExchange(uint8_t *datain, size_t datainlen, uint8_t *dataout, uint32_t *outlen) {
	*outlen = 0;

	if (fexecutor == nullptr)
		return;

	auto resstr = bstr(apdu_result, 0, sizeof(apdu_result) - 10);
	auto apdu = bstr(datain, datainlen);

    printf_device("================\na>> "); dump_hex(apdu, 16);
    fexecutor->Execute(apdu, resstr);
    printf_device("a<< "); dump_hex(resstr, 16);

    *outlen = resstr.length();
    memcpy(dataout, apdu_result, *outlen);
    
    // finish operation and then reset
    DoReset = fsecurity->DoReset;

    return;
}

void OpenpgpInit() {
    printf_device("-------- INIT --------\n");

    hwinit();
    printf_device("Init hardware: ok\n");

    Factory::SoloFactory &factory = Factory::SoloFactory::GetSoloFactory();
    factory.Init();

    Applet::APDUExecutor executor = factory.GetAPDUExecutor();
    fexecutor = &executor;

    OpenPGP::OpenPGPFactory &opgp_factory = factory.GetOpenPGPFactory();
    OpenPGP::Security &security = opgp_factory.GetSecurity();
    fsecurity = &security;    
    printf_device("OpenPGP init: ok.\n");

    return;
}
