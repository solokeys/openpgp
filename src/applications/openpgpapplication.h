/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_OPENPGPAPPLICATION_H_
#define SRC_OPENPGPAPPLICATION_H_

#include "application.h"
#include "openpgp/openpgpfactory.h"
#include "openpgp/openpgpconst.h"
#include "openpgp/openpgpstruct.h"

namespace Application {

class OpenPGPApplication: public Application {
    // TODO: application state. INIT/WORK. save/load to file
    OpenPGP::ApplicationState state;
	OpenPGP::ApplicationConfig config;
	OpenPGP::PWStatusBytes pwstatus;

private:
	// OpenPGP AID
	const bstr aid = "\xd2\x76\x00\x01\x24\x01"_bstr;
public:
	OpenPGPApplication();

	virtual const bstr *GetAID();

	virtual Util::Error APDUExchange(APDUStruct &apdu, bstr &result);
	virtual Util::Error Select(bstr &result);
};

} // namespace Application


#endif /* SRC_OPENPGPAPPLICATION_H_ */
