/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_OPENPGPAPPLET_H_
#define SRC_APPLETS_OPENPGPAPPLET_H_

#include "applet.h"
#include "openpgp/openpgpfactory.h"

namespace Applet {

struct OpenPGPAppletState {
	bool pw1Authenticated;
	bool pw3Authenticated;
};

// OpenPGP v3.3.1 page 78
enum LifeCycleState {
	Created     = 0x01,
	Init        = 0x03,
	Operational = 0x04,
	Terminated  = 0x05,
};

struct OpenPGPAppletConfig {
	LifeCycleState state;
};

class OpenPGPApplet: public Applet {
	// TODO: applet state. INIT/WORK. save/load to file
	OpenPGPAppletState state;
	OpenPGPAppletConfig config;

private:
	// OpenPGP AID
	const bstr aid = "\xd2\x76\x00\x01\x24\x01"_bstr;
public:
	OpenPGPApplet();

	virtual const bstr *GetAID();

	virtual Util::Error APDUExchange(bstr apdu, bstr &result);
};

}


#endif /* SRC_APPLETS_OPENPGPAPPLET_H_ */
