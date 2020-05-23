# Ledger App for Burst

(Still under development)
This is the official [Burst](https://burst-coin.org) ledger wallet app for the Ledger Nano S and X devices.
Initially forked from [app-ledger-ardor](https://github.com/jelurida-dev/app-ledger-ardor-main) but mostly rewritten.

This application supports multiple accounts using BIP32 derivation paths.
No information is stored on the device flash memory.

## Documentation

[Burst Wiki](https://burstwiki.org/en/), [Ledger Documentation Hub](https://ledger.readthedocs.io/en/latest/)

## Supported Wallets
 - [BTDEX](https://btdex.trade/), ([documentation](https://medium.com/@jjos2372/how-to-use-a-ledger-nano-s-with-btdex-to-secure-your-burst-and-trt-3522db9afc34))

## Developer Resources 

### Prepare the environment

Only Linux is supported as a development OS. For Windows and MacOS users, a Linux VM is recommended.

Using Ledger Live, **update your Ledger Dongle to the latest firmware (>= 1.6.0)**.

Make sure you can connect to your device, add the following [udev rules](https://github.com/LedgerHQ/udev-rules)
(or check for more details on [this Ledger article](https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues)):
```bash
wget -q -O - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```

After that, install prerequisite packages:

```bash
sudo apt install python3-venv python3-dev libudev-dev libusb-1.0-0-dev libtinfo.so.5
```

Now use the `prepare-devenv.sh` script to prepare a local development environment with either `s` or `x`.

```bash
# (x or s, depending on your device)
source prepare-devenv.sh s
```

### Test the app

After loading the app on your device, run the test script and *authorize* the transactions on the device:
```bash
python test.py
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

## How to interact with the device (APDU Protocol)

Commands are in the format of
```
    0x80 <command id byte> <p1 byte> <p2 byte> <buffer length> <buffer>
```

Response buffers are usually in the form of
```
    <return value byte> <buffer> <0x90> <0x00>
```

`return_values.h` lists all possible return values for the Burstcoin app

Use the `test.py` code as a starting point for your application. You will find the commands for getting the publick key, signing transactions, etc.

## Compilation

To compile (remember to prepare your environment):
```bash
make
```

To compile and upload to the Ledger device:
```bash
make load
```

### Stack Overflow Canary

To get the amount of memory used in the app call the following command

```bash
readelf -s bin/app.elf | grep app_stack_canary 
```

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

All Burst wallets up to now derive the private key based on a [SHA-256 of the passphrase](https://github.com/burst-apps-team/burstkit4j/blob/c87793a4b76cc881f6596283a5bdbbc3ff1dde58/burstKit/src/main/java/burst/kit/crypto/BurstCryptoImpl.java#L125).
This is not how BIP32 wallets work, thus you will not be able to use your ledger *recovery phrase* directly on *legacy* Burst wallets, **only using another BIP32 device**.

Burst is a registered [BIP-0044 coin](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) with type equals `30` (or `0x8000001e`).
So, a key derivation was implemented for Ledger devices using Curve25519 with the following path:
```
44'/30'/account'/change'/index'
```

Wallets can send different values for `account`, `change`, and `index`. A simple implementation could always send `account=0` and `change=0`, leaving
the `index` for identifying different accounts (addresses).

## Signatures

Burst signatures are not supported natively by Ledger.
So the [Curve25519 Burst signature](https://github.com/burst-apps-team/burstkit4j/blob/c87793a4b76cc881f6596283a5bdbbc3ff1dde58/burstKit/src/main/java/burst/kit/crypto/ec/Curve25519Impl.java#L35) was implemented on this Ledger App.


## License

This code is licensed under [Apache-2](LICENSE).

## Author

jjos

Donation address: BURST-JJQS-MMA4-GHB4-4ZNZU

(Initially forked from [app-ledger-ardor](https://github.com/jelurida-dev/app-ledger-ardor-main).)
