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

Applet::APDUExecutor *fexecutor = nullptr;
void OpenpgpExchange(uint8_t *datain, size_t datainlen, uint8_t *dataout, uint32_t *outlen) {
	*outlen = 0;

	if (fexecutor == nullptr)
		return;

	uint8_t apdu_result[4096] = {0};
	auto resstr = bstr(apdu_result, 0, sizeof(apdu_result) - 10);
	auto apdu = bstr(datain, datainlen);

	printf_device("================\na>> "); dump_hex(apdu);
    fexecutor->Execute(apdu, resstr);
    printf_device("a<< "); dump_hex(resstr);

    *outlen = resstr.length();
    memcpy(dataout, apdu_result, *outlen);

    return;
}

void OpenpgpInit() {

    printf_device("-------- INIT --------\n");

    hwinit();
    printf_device("Init hardware: ok\n");

    Factory::SoloFactory &factory = Factory::SoloFactory::GetSoloFactory();
    factory.Init();
    printf_device("OpenPGP factory: ok.\n");

    Applet::APDUExecutor executor = factory.GetAPDUExecutor();
    fexecutor = &executor;
    printf_device("OpenPGP executor: ok.\n");

    return;
}
