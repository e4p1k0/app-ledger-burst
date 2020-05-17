# Ledger App for Burst

This is the official [Burst](https://burst-coin.org) ledger wallet app for the Ledger Nano S and X devices.
Initially forked from app-ledger-ardor but transaction parsing and signing were rewritten.

## Documentation

[Burst Wiki](https://burstwiki.org/en/), [Ledger Documentation Hub](https://ledger.readthedocs.io/en/latest/)

## Developer Resources 

### Prepare the environment

First, **update your ledger to the latest firmware**.

After that, install prerequisite packages:

```bash
sudo apt install python3-venv python3-dev libudev-dev libusb-1.0-0-dev libtinfo.so.5
```

Now use the `prepare-devenv.sh` script to prepare a local development environment with the right target (`s` or `x`).

```bash
# (x or s, depending on your device)
source prepare-devenv.sh s
```

### Enable Log Messages (optional)

To turn on logging on the Ledger app
1. Install the [debug firmware](https://ledger.readthedocs.io/en/latest/userspace/debugging.html)
2. Enable debugging in the makefile (DEVEL = 1) - make sure not to commit this change
3. Execute `make clean` and then `make load` to generate the source code for all the PRINTF statements

### Zero Tolerance for Compilation Warnings

No compilation warnings in committed code please! 

You can ignore warnings coming out of OS library files, `curve25519_i64.c`, `curveConversion.c` and the `aes` folder
since they are externally imported.

### State Cleaning

Since we use a union data type for command handlers state (`states_t` in `burst.h`) to save memory, make sure to **clear this state**
to avoid some attack vectors. 

This is done by passing `true` in the `isLastCommandDifferent` parameter of the handler function. In this case the handler has 
to clear the state before using it.

In addition state must be cleared whenever we get an error in a handler function which manages state.

### More Code Design

Do not include statement for C source code inside other C source code to prevent complicating the dependencies.

Store constants and hardcoded values in config.h

### Code Flow

The code flow starts at burst_main (`main.c`) which uses a global try/catch to prevent the app from crashing on error. 
The code loops on io_exchange waiting for the next command buffer, then calling the appropriate handler function 
implemented in the different .c files.

## APDU Protocol

Commands are in the format of

    0xE0 <command id byte> <p1 byte> <p2 byte> <sizeof buffer> <buffer>

Response buffers are usually in the form of

    <return value byte> <buffer> <0x90> <0x00>

returnValues.h lists all the return statuses

## Compilation

To compile call

	make

To compile and upload to the ledger device

	make load

### Stack Overflow Canary

To get the amount of memory used in the app call the following command

    readelf -s bin/app.elf | grep app_stack_canary 

This will output the canary (which is at the end of the memory space) location then subtract `0x20001800` (Nano S) or
`0xda7a0000` (Nano X) to get the actual used up space for the app. 
The NanoS device has 4k of memory for the app and stack.

The app uses the SDK's built in app_stack_canary, it's activated in the makefile by the define `HAVE_BOLOS_APP_STACK_CANARY`
We advise to keep this flag always on, it just gives extra security and doesn't take up much CPU.
The way this works is it defines an int at the end of the stack, initializes it at startup and then check's against it every 
call to io_exchange, if it changes it throws an `EXCEPTION_IO_RESET`, which should reset the app.
In order to debug a stack overflow, call check_canary() add different parts of the code to check if you have overflowed the stack.

### Error Handling

Errors are propagated through the call stack and it's the command handler's or button handler's job to respond accordingly,
clear the state if they manage it, and return the error back to the caller.

All return values for functions should be checked in every function.

## Key Derivation Algorithm

Burst signatures are based on the EC-KCDSA over Curve25519 algorithm which is not supported natively by Ledger.

To support standard BIP32 key derivation we implemented curve conversion for Burst using the protocol 
[Yaffe-Bender HD key derivation for EC-KCDSA](https://www.jelurida.com/sites/default/files/kcdsa.pdf)

Technically a public key is a Point (X,Y) on a curve C. X,Y are integers modulo some field F with a base point on the curve G.
The tuple (C, F, G) defines a "curve", in this paper we are dealing with the twisted edwards curve (ed25519) and curve25519.

We are using a morph function between ed25519 and curve25519 so that if Apoint = Knumber * BasePointED25519 on ed25519 then 
morph(Apoint) = Knumber * BasePointECKCDSA on curve25119
Implementation for this function can be found in curveConversion.c

ed25519 public key is defined as `PublicKeyED25519Point = CLAMP(SHA512(privateKey)[:32]) * ED25519BasePoint`

Let's refer to CLAMP(SHA512(privateKey)[:32]) as KL

The derivation composition flow for path P is:

1. os_perso_derive_node_bip32 derives KLKR and chaincode for P using SLIP10 initialization on 512 bits master seed from bip39/bip32 24 words
2. Derive PublicKeyED25519 using cx_eddsa_get_public_key and KL, the point is encoded as 65 bytes 0x04 XBigEndian YBigEndian
3. PubleyKeyED25519YLE = convert(YBigEndian) - just reverse the bytes
4. PublicKeyCurve25519X = morph(PubleyKeyEED25519YLE)

Points on Curve25519 can be defined by the X coordinate (since each X coordinate has only one matching Y coordinate) 
so PublicKeyCurve25519X and KL should hold PublicKeyCurve25519X = KL * Curve25519BasePoint

In EC-KCDSA publickey = privatekey^-1 * BasePoint, privateKey^-1 is referred to as the key seed, so KL is the key seed for the PublicKeyCurve25519X public key for path P.

Extra Notes:

* ED25519 public keys are compressed into a Y point in little endian encoding having the MSB bit encode the parity of X (since each Y coordinate has two possible X values, X and -X in field F which means if one is even the second is odd)

* In order to derive public keys outside of the ledger (Master key derivation), all we need is the ed25519 public key and chaincode, described in the derivation scheme.

* Reference code for the derivation implementation can found in the [Ardor source code](https://bitbucket.org/Jelurida/ardor/src/master/)